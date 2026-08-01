/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2009 Friedrich Schöller <hans@schoeller.se>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include "transport.h"

#include <arpa/inet.h>
#include <string.h>

namespace
{
    const size_t DIRECT_ACK_RESERVE = 512;
}

namespace
{
    void put16(char *buffer, uint16_t value)
    {
        value = htons(value);
        memcpy(buffer, &value, sizeof(value));
    }

    void put32(char *buffer, uint32_t value)
    {
        value = htonl(value);
        memcpy(buffer, &value, sizeof(value));
    }

    uint16_t get16(const char *buffer)
    {
        uint16_t value;
        memcpy(&value, buffer, sizeof(value));
        return ntohs(value);
    }

    uint32_t get32(const char *buffer)
    {
        uint32_t value;
        memcpy(&value, buffer, sizeof(value));
        return ntohl(value);
    }
}

TransportV3::Header::Header()
{
    flags = FLAG_NONE;
    mode = MODE_CREDIT;
    creditTarget = 0;
    sessionId = 0;
    txSequence = 0;
    ackSequence = 0;
    ackBits = 0;
    queuedPackets = 0;
    timestamp = 0;
}

void TransportV3::encode(char *buffer, const Header &header)
{
    memset(buffer, 0, HEADER_SIZE);
    buffer[0] = VERSION;
    buffer[1] = header.flags;
    buffer[2] = header.mode;
    buffer[3] = header.creditTarget;
    put32(buffer + 4, header.sessionId);
    put32(buffer + 8, header.txSequence);
    put32(buffer + 12, header.ackSequence);
    put32(buffer + 16, header.ackBits);
    put16(buffer + 20, header.queuedPackets);
    put16(buffer + 22, header.timestamp);
}

bool TransportV3::decode(const char *buffer, int length, Header &header)
{
    if (length < HEADER_SIZE || (uint8_t)buffer[0] != VERSION)
        return false;

    header.flags = (uint8_t)buffer[1];
    header.mode = (uint8_t)buffer[2];
    header.creditTarget = (uint8_t)buffer[3];
    header.sessionId = get32(buffer + 4);
    header.txSequence = get32(buffer + 8);
    header.ackSequence = get32(buffer + 12);
    header.ackBits = get32(buffer + 16);
    header.queuedPackets = get16(buffer + 20);
    header.timestamp = get16(buffer + 22);

    return header.mode == MODE_CREDIT || header.mode == MODE_DIRECT;
}

bool TransportV3::sequenceAfter(uint32_t first, uint32_t second)
{
    return (int32_t)(first - second) > 0;
}

bool TransportV3::acknowledged(uint32_t sequence, uint32_t ackSequence,
                               uint32_t ackBits)
{
    if (sequence == 0 || ackSequence == 0)
        return false;
    if (sequence == ackSequence)
        return true;
    if (!sequenceAfter(ackSequence, sequence))
        return false;

    uint32_t distance = ackSequence - sequence;
    return distance <= 32 && (ackBits & (1u << (distance - 1))) != 0;
}

SequenceTracker::SequenceTracker()
{
    largest = 0;
    receivedBits = 0;
}

bool SequenceTracker::accept(uint32_t sequence)
{
    if (sequence == 0)
        return false;

    if (largest == 0)
    {
        largest = sequence;
        return true;
    }

    if (TransportV3::sequenceAfter(sequence, largest))
    {
        uint32_t distance = sequence - largest;
        if (distance > 32)
            receivedBits = 0;
        else
        {
            receivedBits <<= distance;
            receivedBits |= 1u << (distance - 1);
        }
        largest = sequence;
        return true;
    }

    uint32_t distance = largest - sequence;
    if (distance == 0 || distance > 32)
        return false;

    uint32_t bit = 1u << (distance - 1);
    if ((receivedBits & bit) != 0)
        return false;
    receivedBits |= bit;
    return true;
}

DirectAckTracker::DirectAckTracker()
{
    entries.reserve(DIRECT_ACK_RESERVE);
}

DirectAckTracker::DirectAckTracker(const DirectAckTracker &other)
    : entries(other.entries)
{
    if (entries.capacity() < DIRECT_ACK_RESERVE)
        entries.reserve(DIRECT_ACK_RESERVE);
}

DirectAckTracker &DirectAckTracker::operator=(const DirectAckTracker &other)
{
    if (this != &other)
    {
        entries = other.entries;
        if (entries.capacity() < DIRECT_ACK_RESERVE)
            entries.reserve(DIRECT_ACK_RESERVE);
    }
    return *this;
}

void DirectAckTracker::record(uint32_t sequence, int64_t sentMilliseconds)
{
    Entry entry;
    entry.sequence = sequence;
    entry.sentMilliseconds = sentMilliseconds;
    entries.push_back(entry);
}

void DirectAckTracker::acknowledge(uint32_t ackSequence, uint32_t ackBits)
{
    size_t writeIndex = 0;
    for (size_t readIndex = 0; readIndex < entries.size(); ++readIndex)
    {
        const Entry &entry = entries[readIndex];
        bool beyondAckWindow = ackSequence != 0 &&
            TransportV3::sequenceAfter(ackSequence, entry.sequence) &&
            ackSequence - entry.sequence > 32;
        if (beyondAckWindow ||
            TransportV3::acknowledged(entry.sequence, ackSequence, ackBits))
            continue;
        if (writeIndex != readIndex)
            entries[writeIndex] = entry;
        ++writeIndex;
    }
    entries.resize(writeIndex);
}

bool DirectAckTracker::failed(int64_t nowMilliseconds,
                              size_t minimumOutstanding,
                              int timeoutMilliseconds) const
{
    if (entries.size() < minimumOutstanding)
        return false;
    for (size_t i = 0; i < entries.size(); ++i)
        if (nowMilliseconds > entries[i].sentMilliseconds + timeoutMilliseconds)
            return true;
    return false;
}

AdaptiveCredit::AdaptiveCredit(int minimum, int maximum, int initial)
{
    minTarget = minimum < 1 ? 1 : minimum;
    maxTarget = maximum < minTarget ? minTarget : maximum;
    initialTarget = initial < minTarget ? minTarget : initial;
    if (initialTarget > maxTarget)
        initialTarget = maxTarget;
    reset();
}

void AdaptiveCredit::reset()
{
    currentTarget = initialTarget;
    smoothedRttMs = 200;
    rttVariationMs = 100;
    retransmissionTimeoutMs = 1000;
    haveRttSample = false;
    growthAcks = 0;
    idleTicks = 0;
}

void AdaptiveCredit::onReply(unsigned int queuedPackets, int rttSampleMs)
{
    if (rttSampleMs > 0 && rttSampleMs < 60000)
    {
        if (!haveRttSample)
        {
            smoothedRttMs = rttSampleMs;
            rttVariationMs = rttSampleMs / 2;
            haveRttSample = true;
        }
        else
        {
            int difference = smoothedRttMs - rttSampleMs;
            if (difference < 0) difference = -difference;
            rttVariationMs = (rttVariationMs * 3 + difference) / 4;
            smoothedRttMs = (smoothedRttMs * 7 + rttSampleMs) / 8;
        }
        int margin = rttVariationMs * 4;
        if (margin < 100) margin = 100;
        retransmissionTimeoutMs = smoothedRttMs + margin;
        if (retransmissionTimeoutMs < 250) retransmissionTimeoutMs = 250;
        if (retransmissionTimeoutMs > 10000) retransmissionTimeoutMs = 10000;
    }

    if (queuedPackets == 0)
    {
        // An unused credit costs no recurring traffic: the server simply
        // retains its echo token until data is ready. Do not shrink based on
        // a burst ending, because bursty TCP would make the target oscillate.
        // Explicit, time-based idle policy can use onIdleTick().
        if (growthAcks > 0)
            growthAcks--;
        return;
    }

    idleTicks = 0;
    unsigned int evidence = queuedPackets;
    if (evidence > (unsigned int)currentTarget)
        evidence = currentTarget;
    growthAcks += evidence;
    if (growthAcks >= currentTarget && currentTarget < maxTarget)
    {
        int increase = currentTarget < 16 ? 2 : currentTarget / 4;
        if (increase < 1)
            increase = 1;
        currentTarget += increase;
        if (currentTarget > maxTarget)
            currentTarget = maxTarget;
        growthAcks = 0;
    }
}

void AdaptiveCredit::onTimeout()
{
    currentTarget /= 2;
    if (currentTarget < minTarget)
        currentTarget = minTarget;
    growthAcks = 0;
    idleTicks = 0;
    retransmissionTimeoutMs *= 2;
    if (retransmissionTimeoutMs > 10000)
        retransmissionTimeoutMs = 10000;
}

void AdaptiveCredit::onIdleTick()
{
    idleTicks++;
    if (idleTicks >= 4 && currentTarget > minTarget)
    {
        currentTarget--;
        idleTicks = 0;
    }
}

int AdaptiveCredit::timeoutMs() const
{
    return retransmissionTimeoutMs;
}
