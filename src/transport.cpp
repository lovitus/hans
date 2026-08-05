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
#include "config.h"

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

uint8_t TransportV3::advertisedCapabilities(bool adaptive,
                                             bool windowsIcmpHelper)
{
    uint8_t capabilities = adaptive ? ALL_CAPABILITIES : CAP_SEQUENCE_ACK;
    if (windowsIcmpHelper)
    {
        /* IcmpSendEcho2 only delivers replies associated with live requests.
         * A few overlapping credit requests can make the direct probe pass,
         * but they expire and cannot sustain unsolicited server traffic. */
        capabilities &= (uint8_t)~CAP_DIRECT_REPLY;
        capabilities |= CAP_WINDOWS_ICMP_HELPER;
    }
    return capabilities;
}

bool TransportV3::requiresImmediateReply(bool windowsIcmpHelper,
                                         bool dataPacket)
{
    return windowsIcmpHelper && dataPacket;
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

void TransportV3::advanceEchoToken(uint16_t &id, uint16_t &sequence)
{
    sequence++;
    if (sequence == 0)
        id++;
}

SequenceTracker::SequenceTracker()
{
    largest = 0;
    receivedBits = 0;
    acceptedPackets = 0;
    duplicatePackets = 0;
    gapEvents = 0;
    missingPackets = 0;
    latePackets = 0;
}

bool SequenceTracker::accept(uint32_t sequence)
{
    if (sequence == 0)
    {
        duplicatePackets++;
        return false;
    }

    if (largest == 0)
    {
        largest = sequence;
        acceptedPackets++;
        return true;
    }

    if (TransportV3::sequenceAfter(sequence, largest))
    {
        uint32_t distance = sequence - largest;
        if (distance > 1)
        {
            gapEvents++;
            missingPackets += distance - 1;
        }
        if (distance > 32)
            receivedBits = 0;
        else if (distance == 32)
            receivedBits = 1u << 31;
        else
        {
            receivedBits <<= distance;
            receivedBits |= 1u << (distance - 1);
        }
        largest = sequence;
        acceptedPackets++;
        return true;
    }

    uint32_t distance = largest - sequence;
    if (distance == 0 || distance > 32)
    {
        duplicatePackets++;
        return false;
    }

    uint32_t bit = 1u << (distance - 1);
    if ((receivedBits & bit) != 0)
    {
        duplicatePackets++;
        return false;
    }
    receivedBits |= bit;
    acceptedPackets++;
    latePackets++;
    return true;
}

TransportReorderBuffer::TransportReorderBuffer()
{
    initialized = false;
    enabled = false;
    expected = 0;
    gapSinceMilliseconds = 0;
    bufferedPackets = 0;
    releasedGaps = 0;
    skippedSequences = 0;
    lateReleases = 0;
    maxDepth = 0;
    items.reserve(HANS_TRANSPORT_REORDER_MAX_PACKETS);
}

uint32_t TransportReorderBuffer::nextSequence(uint32_t sequence)
{
    sequence++;
    return sequence == 0 ? 1 : sequence;
}

size_t TransportReorderBuffer::find(uint32_t sequence) const
{
    for (size_t i = 0; i < items.size(); ++i)
        if (items[i].sequence == sequence)
            return i;
    return items.size();
}

void TransportReorderBuffer::drain(
    std::vector<std::vector<char> > &ready)
{
    while (true)
    {
        size_t index = find(expected);
        if (index == items.size())
            break;
        bool isData = items[index].isData;
        if (isData)
        {
            ready.push_back(std::vector<char>());
            ready.back().swap(items[index].data);
        }
        size_t last = items.size() - 1;
        if (index != last)
        {
            items[index].sequence = items[last].sequence;
            items[index].isData = items[last].isData;
            items[index].data.swap(items[last].data);
        }
        items.pop_back();
        expected = nextSequence(expected);
    }
    if (items.empty())
        gapSinceMilliseconds = 0;
}

bool TransportReorderBuffer::releaseGap(
    int64_t nowMilliseconds, std::vector<std::vector<char> > &ready)
{
    if (items.empty())
        return false;

    size_t nearest = items.size();
    uint32_t nearestDistance = 0;
    for (size_t i = 0; i < items.size(); ++i)
    {
        if (!TransportV3::sequenceAfter(items[i].sequence, expected))
            continue;
        uint32_t distance = items[i].sequence - expected;
        if (nearest == items.size() || distance < nearestDistance)
        {
            nearest = i;
            nearestDistance = distance;
        }
    }
    if (nearest == items.size())
        return false;

    skippedSequences += nearestDistance;
    releasedGaps++;
    expected = items[nearest].sequence;
    gapSinceMilliseconds = 0;
    drain(ready);
    if (!items.empty())
        gapSinceMilliseconds = nowMilliseconds;
    return true;
}

TransportReorderBuffer::Action TransportReorderBuffer::observe(
    uint32_t sequence, bool isData, const char *data, int length,
    int64_t nowMilliseconds, std::vector<std::vector<char> > &ready)
{
    if (!initialized)
    {
        initialized = true;
        expected = sequence;
    }

#if HANS_TRANSPORT_REORDER_DELAY_MS <= 0
    expected = nextSequence(sequence);
    return isData ? DELIVER_CURRENT : IGNORE_CURRENT;
#else
    // Do not turn ordinary loss into head-of-line blocking. The caller enables
    // buffering only after its sequence tracker has observed a packet that
    // really arrived late, proving that this peer/path can reorder traffic.
    if (!enabled)
    {
        expected = nextSequence(sequence);
        return isData ? DELIVER_CURRENT : IGNORE_CURRENT;
    }

    if (sequence == expected)
    {
        expected = nextSequence(expected);
        drain(ready);
        return isData ? DELIVER_CURRENT : IGNORE_CURRENT;
    }

    if (!TransportV3::sequenceAfter(sequence, expected))
    {
        if (isData)
        {
            lateReleases++;
            return DELIVER_CURRENT;
        }
        return IGNORE_CURRENT;
    }

    items.push_back(Item());
    Item &item = items.back();
    item.sequence = sequence;
    item.isData = isData;
    if (isData && length > 0)
        item.data.assign(data, data + length);
    bufferedPackets++;
    if (items.size() > maxDepth)
        maxDepth = items.size();
    if (gapSinceMilliseconds == 0)
        gapSinceMilliseconds = nowMilliseconds;

    if (items.size() >= HANS_TRANSPORT_REORDER_MAX_PACKETS)
        releaseGap(nowMilliseconds, ready);
    return HOLD_CURRENT;
#endif
}

bool TransportReorderBuffer::flushExpired(
    int64_t nowMilliseconds, std::vector<std::vector<char> > &ready)
{
#if HANS_TRANSPORT_REORDER_DELAY_MS <= 0
    (void)nowMilliseconds;
    (void)ready;
    return false;
#else
    if (items.empty() || gapSinceMilliseconds == 0 ||
        nowMilliseconds - gapSinceMilliseconds < HANS_TRANSPORT_REORDER_DELAY_MS)
        return false;
    return releaseGap(nowMilliseconds, ready);
#endif
}

int TransportReorderBuffer::waitMilliseconds(int64_t nowMilliseconds) const
{
#if HANS_TRANSPORT_REORDER_DELAY_MS <= 0
    (void)nowMilliseconds;
    return -1;
#else
    if (items.empty() || gapSinceMilliseconds == 0)
        return -1;
    int64_t remaining = HANS_TRANSPORT_REORDER_DELAY_MS -
                        (nowMilliseconds - gapSinceMilliseconds);
    return remaining > 0 ? (int)remaining : 0;
#endif
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
