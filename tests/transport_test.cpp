#include "../src/transport.h"
#include "../src/config.h"

#include <assert.h>
#include <string.h>
#include <iostream>

static void testHeaderRoundTrip()
{
    char buffer[TransportV3::HEADER_SIZE];
    TransportV3::Header sent;
    sent.flags = TransportV3::FLAG_CONTROL | TransportV3::FLAG_DIRECT;
    sent.mode = TransportV3::MODE_DIRECT;
    sent.creditTarget = 73;
    sent.sessionId = 0x12345678;
    sent.txSequence = 0xfedcba98;
    sent.ackSequence = 0x76543210;
    sent.ackBits = 0xa5a55a5a;
    sent.queuedPackets = 513;
    sent.timestamp = 65530;

    TransportV3::encode(buffer, sent);
    TransportV3::Header received;
    assert(TransportV3::decode(buffer, sizeof(buffer), received));
    assert(received.flags == sent.flags);
    assert(received.mode == sent.mode);
    assert(received.creditTarget == sent.creditTarget);
    assert(received.sessionId == sent.sessionId);
    assert(received.txSequence == sent.txSequence);
    assert(received.ackSequence == sent.ackSequence);
    assert(received.ackBits == sent.ackBits);
    assert(received.queuedPackets == sent.queuedPackets);
    assert(received.timestamp == sent.timestamp);
    assert(!TransportV3::decode(buffer, TransportV3::HEADER_SIZE - 1, received));

    char malformed[TransportV3::HEADER_SIZE];
    memcpy(malformed, buffer, sizeof(malformed));
    malformed[0] = TransportV3::VERSION + 1;
    assert(!TransportV3::decode(malformed, sizeof(malformed), received));
    memcpy(malformed, buffer, sizeof(malformed));
    malformed[2] = (char)0xff;
    assert(!TransportV3::decode(malformed, sizeof(malformed), received));
}

static void testSequenceTracking()
{
    SequenceTracker tracker;
    assert(tracker.accept(10));
    assert(tracker.accept(12));
    assert(tracker.accept(11));
    assert(!tracker.accept(11));
    assert(!tracker.accept(12));
    assert(tracker.ackSequence() == 12);
    assert(TransportV3::acknowledged(12, tracker.ackSequence(), tracker.ackBits()));
    assert(TransportV3::acknowledged(11, tracker.ackSequence(), tracker.ackBits()));
    assert(TransportV3::acknowledged(10, tracker.ackSequence(), tracker.ackBits()));
    assert(!TransportV3::acknowledged(9, tracker.ackSequence(), tracker.ackBits()));

    SequenceTracker wrapped;
    assert(wrapped.accept(0xfffffffeu));
    assert(wrapped.accept(0xffffffffu));
    assert(wrapped.accept(1));
    assert(wrapped.ackSequence() == 1);
    assert(TransportV3::acknowledged(0xffffffffu, wrapped.ackSequence(),
                                     wrapped.ackBits()));
    assert(!wrapped.accept(0));

    SequenceTracker distant;
    assert(distant.accept(100));
    assert(distant.accept(140));
    assert(!distant.accept(100));
    assert(!TransportV3::acknowledged(100, distant.ackSequence(),
                                      distant.ackBits()));
}

static void testAdaptiveCredit()
{
    AdaptiveCredit credit(2, 32, 4);
    assert(credit.target() == 4);
    assert(credit.timeoutMs() == 1000);

    credit.onReply(8, 100);
    assert(credit.target() == 6);
    assert(credit.rttMs() == 100);
    assert(credit.timeoutMs() == 300);

    for (int i = 0; i < 3; ++i)
        credit.onReply(8, 100);
    assert(credit.target() == 10);

    for (int i = 0; i < 6; ++i)
        credit.onReply(4, 100);
    assert(credit.target() > 10 && credit.target() <= 32);

    int beforeTimeout = credit.target();
    int beforeRto = credit.timeoutMs();
    credit.onTimeout();
    assert(credit.target() == beforeTimeout / 2);
    assert(credit.timeoutMs() == beforeRto * 2);
    while (credit.target() > 2)
        credit.onTimeout();
    assert(credit.target() == 2);
    assert(credit.timeoutMs() <= 10000);

    credit.reset();
    for (int i = 0; i < 8; ++i)
        credit.onReply(0, 200);
    assert(credit.target() == 4);
    for (int i = 0; i < 4; ++i)
        credit.onIdleTick();
    assert(credit.target() == 3);
}

static void testWindowsCreditLifetime()
{
    assert(WINDOWS_ICMP_REQUEST_TIMEOUT_MS > CREDIT_REFRESH_MS);
    assert(WINDOWS_ICMP_MAX_CREDITS * 2 <= WINDOWS_ICMP_MAX_PENDING);
    assert((TransportV3::ALL_CAPABILITIES &
            TransportV3::CAP_WINDOWS_ICMP_HELPER) == 0);
}

static void testDirectAckTracker()
{
    DirectAckTracker tracker;
    assert(tracker.capacity() >= 512);
    tracker.record(100, 1000);
    tracker.record(101, 1100);
    tracker.record(102, 1200);
    assert(tracker.size() == 3);
    assert(!tracker.failed(3999, 3, 3000));
    assert(tracker.failed(4001, 3, 3000));

    // Cumulative/selective ACK keeps only sequence 101 outstanding.
    tracker.acknowledge(102, 0x2);
    assert(tracker.size() == 1);
    tracker.acknowledge(103, 0x3);
    assert(tracker.size() == 0);

    // Entries older than the 32-bit selective ACK window are retired exactly
    // like the previous std::map implementation, including sequence wrap.
    tracker.record(10, 1);
    tracker.record(100, 2);
    tracker.acknowledge(100, 0);
    assert(tracker.size() == 0);
    tracker.record(0xffffffffu, 3);
    tracker.record(1, 4);
    tracker.acknowledge(1, 0x2);
    assert(tracker.size() == 0);

    DirectAckTracker reserved;
    size_t initialCapacity = reserved.capacity();
    DirectAckTracker copied(reserved);
    assert(copied.capacity() == initialCapacity);
    for (uint32_t sequence = 1; sequence <= 512; ++sequence)
        reserved.record(sequence, sequence);
    assert(reserved.capacity() == initialCapacity);
    reserved.acknowledge(600, 0);
    assert(reserved.size() == 0);
}

int main()
{
    testHeaderRoundTrip();
    testSequenceTracking();
    testAdaptiveCredit();
    testWindowsCreditLifetime();
    testDirectAckTracker();
    std::cout << "OK: transport v3 codec, ACK window, and adaptive credit tests passed\n";
    return 0;
}
