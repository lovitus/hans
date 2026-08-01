#include "../src/transport.h"
#include "../src/userspace.h"

#include <assert.h>
#include <stdio.h>
#include <string>
#include <vector>

namespace
{
    unsigned int state = 0x7357a11u;

    unsigned int nextRandom()
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }
}

int main()
{
    char packet[256];
    for (int iteration = 0; iteration < 50000; ++iteration)
    {
        int length = (int)(nextRandom() % sizeof(packet));
        for (int i = 0; i < length; ++i)
            packet[i] = (char)nextRandom();
        TransportV3::Header header;
        bool valid = TransportV3::decode(packet, length, header);
        if (valid)
        {
            assert(length >= TransportV3::HEADER_SIZE);
            assert(header.mode == TransportV3::MODE_CREDIT ||
                   header.mode == TransportV3::MODE_DIRECT);
        }
    }

    const char alphabet[] = "0123456789,=.:abcdefXYZ-[]";
    for (int iteration = 0; iteration < 20000; ++iteration)
    {
        std::string input;
        size_t length = nextRandom() % 96;
        for (size_t i = 0; i < length; ++i)
            input += alphabet[nextRandom() % (sizeof(alphabet) - 1)];
        std::vector<SharePort> ports;
        std::string error;
        if (UserspaceNetwork::parseSharePorts(input, ports, error))
        {
            assert(!ports.empty());
            for (size_t i = 0; i < ports.size(); ++i)
            {
                assert(ports[i].listenPort != 0);
                assert(ports[i].targetPort != 0);
                for (size_t j = 0; j < i; ++j)
                    assert(ports[i].listenPort != ports[j].listenPort);
            }
        }
    }

    puts("OK: deterministic transport and configuration parser fuzz tests passed");
    return 0;
}
