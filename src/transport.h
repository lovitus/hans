/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2009 Friedrich Schöller <hans@schoeller.se>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <vector>

class TransportV3
{
public:
    enum
    {
        HEADER_SIZE = 24,
        VERSION = 1,
        CAP_ADAPTIVE_CREDIT = 1,
        CAP_DIRECT_REPLY = 2,
        CAP_SEQUENCE_ACK = 4,
        // Client-side platform hint. It is intentionally excluded from
        // ALL_CAPABILITIES because it does not negotiate transport behavior.
        CAP_WINDOWS_ICMP_HELPER = 8,
        ALL_CAPABILITIES = CAP_ADAPTIVE_CREDIT | CAP_DIRECT_REPLY |
                           CAP_SEQUENCE_ACK
    };

    enum Mode
    {
        MODE_CREDIT = 1,
        MODE_DIRECT = 2
    };

    enum Flag
    {
        FLAG_NONE = 0,
        FLAG_CONTROL = 1,
        FLAG_DIRECT = 2
    };

    struct Header
    {
        Header();

        uint8_t flags;
        uint8_t mode;
        uint8_t creditTarget;
        uint32_t sessionId;
        uint32_t txSequence;
        uint32_t ackSequence;
        uint32_t ackBits;
        uint16_t queuedPackets;
        uint16_t timestamp;
    };

    static void encode(char *buffer, const Header &header);
    static bool decode(const char *buffer, int length, Header &header);
    static bool sequenceAfter(uint32_t first, uint32_t second);
    static bool acknowledged(uint32_t sequence, uint32_t ackSequence,
                             uint32_t ackBits);
    static void advanceEchoToken(uint16_t &id, uint16_t &sequence);
    static uint8_t advertisedCapabilities(bool adaptive,
                                          bool windowsIcmpHelper);
    static bool requiresImmediateReply(bool windowsIcmpHelper,
                                       bool dataPacket);
};

class SequenceTracker
{
public:
    SequenceTracker();

    bool accept(uint32_t sequence);
    uint32_t ackSequence() const { return largest; }
    uint32_t ackBits() const { return receivedBits; }
    uint64_t acceptedCount() const { return acceptedPackets; }
    uint64_t duplicateCount() const { return duplicatePackets; }
    uint64_t gapCount() const { return gapEvents; }
    uint64_t missingCount() const { return missingPackets; }
    uint64_t lateCount() const { return latePackets; }

private:
    uint32_t largest;
    uint32_t receivedBits;
    uint64_t acceptedPackets;
    uint64_t duplicatePackets;
    uint64_t gapEvents;
    uint64_t missingPackets;
    uint64_t latePackets;
};

class TransportReorderBuffer
{
public:
    enum Action
    {
        HOLD_CURRENT,
        DELIVER_CURRENT,
        IGNORE_CURRENT
    };

    TransportReorderBuffer();
    void enable()
    {
        if (!enabled)
        {
            enabled = true;
            initialized = false;
            expected = 0;
            gapSinceMilliseconds = 0;
        }
    }
    bool isEnabled() const { return enabled; }

    // Control packets are recorded as zero-copy ordering markers. Data takes
    // the allocation-free DELIVER_CURRENT path unless it actually arrives
    // ahead of a missing sequence.
    Action observe(uint32_t sequence, bool isData, const char *data, int length,
                   int64_t nowMilliseconds,
                   std::vector<std::vector<char> > &ready);
    bool flushExpired(int64_t nowMilliseconds,
                      std::vector<std::vector<char> > &ready);
    int waitMilliseconds(int64_t nowMilliseconds) const;
    bool pending() const { return !items.empty(); }

    uint64_t bufferedCount() const { return bufferedPackets; }
    uint64_t releasedGapCount() const { return releasedGaps; }
    uint64_t skippedCount() const { return skippedSequences; }
    uint64_t lateReleaseCount() const { return lateReleases; }
    size_t maximumDepth() const { return maxDepth; }

private:
    struct Item
    {
        uint32_t sequence;
        bool isData;
        std::vector<char> data;
    };

    static uint32_t nextSequence(uint32_t sequence);
    size_t find(uint32_t sequence) const;
    void drain(std::vector<std::vector<char> > &ready);
    bool releaseGap(int64_t nowMilliseconds,
                    std::vector<std::vector<char> > &ready);

    bool initialized;
    bool enabled;
    uint32_t expected;
    int64_t gapSinceMilliseconds;
    std::vector<Item> items;
    uint64_t bufferedPackets;
    uint64_t releasedGaps;
    uint64_t skippedSequences;
    uint64_t lateReleases;
    size_t maxDepth;
};

class AdaptiveCredit
{
public:
    AdaptiveCredit(int minimum = 2, int maximum = 128,
                   int initial = 4);

    void reset();
    void onReply(unsigned int queuedPackets, int rttSampleMs);
    void onTimeout();
    void onIdleTick();

    int target() const { return currentTarget; }
    int rttMs() const { return smoothedRttMs; }
    int timeoutMs() const;

private:
    int minTarget;
    int maxTarget;
    int initialTarget;
    int currentTarget;
    int smoothedRttMs;
    int rttVariationMs;
    int retransmissionTimeoutMs;
    bool haveRttSample;
    int growthAcks;
    int idleTicks;
};

class DirectAckTracker
{
public:
    DirectAckTracker();
    DirectAckTracker(const DirectAckTracker &other);
    DirectAckTracker &operator=(const DirectAckTracker &other);

    void clear() { entries.clear(); }
    void record(uint32_t sequence, int64_t sentMilliseconds);
    void acknowledge(uint32_t ackSequence, uint32_t ackBits);
    bool failed(int64_t nowMilliseconds, size_t minimumOutstanding,
                int timeoutMilliseconds) const;
    size_t size() const { return entries.size(); }
    size_t capacity() const { return entries.capacity(); }

private:
    struct Entry
    {
        uint32_t sequence;
        int64_t sentMilliseconds;
    };
    std::vector<Entry> entries;
};

#endif
