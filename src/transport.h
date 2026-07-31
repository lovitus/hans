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
};

class SequenceTracker
{
public:
    SequenceTracker();

    bool accept(uint32_t sequence);
    uint32_t ackSequence() const { return largest; }
    uint32_t ackBits() const { return receivedBits; }

private:
    uint32_t largest;
    uint32_t receivedBits;
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
    int growthAcks;
    int idleTicks;
};

#endif
