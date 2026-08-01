#include "../src/secure.h"
#include "../src/transport.h"

#include <assert.h>
#include <string.h>
#include <iostream>
#include <vector>

namespace
{
    struct TunnelHeader
    {
        char magic[4];
        uint8_t type;
    };

    void put32(uint8_t *p, uint32_t value)
    {
        p[0] = (uint8_t)(value >> 24);
        p[1] = (uint8_t)(value >> 16);
        p[2] = (uint8_t)(value >> 8);
        p[3] = (uint8_t)value;
    }

    uint32_t get32(const uint8_t *p)
    {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | p[3];
    }
}

int main()
{
    uint8_t clientSecret[32] = {1};
    uint8_t serverSecret[32] = {2};
    uint8_t psk[32];
    NoiseHandshake::derivePsk("protocol integration", psk);
    NoiseHandshake client(NoiseHandshake::INITIATOR, clientSecret, psk);
    NoiseHandshake server(NoiseHandshake::RESPONDER, serverSecret, psk);

    const uint32_t clientIndex = 0x11223344;
    const uint32_t serverIndex = 0xa1b2c3d4;
    std::vector<uint8_t> noise;
    assert(client.writeMessage1(noise));
    std::vector<uint8_t> init(4 + noise.size());
    put32(&init[0], clientIndex);
    memcpy(&init[4], &noise[0], noise.size());
    assert(get32(&init[0]) == clientIndex);
    assert(server.readMessage1(&init[4], init.size() - 4));

    assert(server.writeMessage2(noise));
    std::vector<uint8_t> response(8 + noise.size());
    put32(&response[0], serverIndex);
    put32(&response[4], clientIndex);
    memcpy(&response[8], &noise[0], noise.size());
    assert(get32(&response[4]) == clientIndex);
    assert(client.readMessage2(&response[8], response.size() - 8));

    uint8_t metadata[48];
    memset(metadata, 0, sizeof(metadata));
    memcpy(metadata, "v4-connect-metadata", 19);
    assert(client.writeMessage3(metadata, sizeof(metadata), noise));
    std::vector<uint8_t> finish(8 + noise.size());
    put32(&finish[0], clientIndex);
    put32(&finish[4], serverIndex);
    memcpy(&finish[8], &noise[0], noise.size());
    std::vector<uint8_t> opened;
    assert(get32(&finish[4]) == serverIndex);
    assert(server.readMessage3(&finish[8], finish.size() - 8, opened));
    assert(opened.size() == sizeof(metadata));
    assert(memcmp(&opened[0], metadata, sizeof(metadata)) == 0);

    SecureTransport clientTransport, serverTransport;
    clientTransport.initialize(serverIndex, clientIndex,
                               client.sendKey(), client.receiveKey());
    serverTransport.initialize(clientIndex, serverIndex,
                               server.sendKey(), server.receiveKey());

    uint8_t plain[TransportV3::HEADER_SIZE + 64];
    TransportV3::Header transport;
    transport.mode = TransportV3::MODE_CREDIT;
    transport.sessionId = 0x01020304;
    transport.txSequence = 1;
    transport.creditTarget = 4;
    TransportV3::encode((char *)plain, transport);
    for (size_t i = TransportV3::HEADER_SIZE; i < sizeof(plain); ++i)
        plain[i] = (uint8_t)i;

    TunnelHeader clientData = {{'h','n','c','4'}, 7};
    std::vector<uint8_t> packet;
    assert(clientTransport.seal((const uint8_t *)&clientData,
                                sizeof(clientData), plain, sizeof(plain), packet));
    assert(get32(&packet[0]) == serverIndex);
    assert(serverTransport.open((const uint8_t *)&clientData,
                                sizeof(clientData), &packet[0], packet.size(), opened));
    TransportV3::Header decoded;
    assert(TransportV3::decode((const char *)&opened[0], opened.size(), decoded));
    assert(decoded.sessionId == transport.sessionId && decoded.txSequence == 1);

    // Direction, message type, receiver index, and replay state all belong
    // to the authenticated protocol contract.
    TunnelHeader wrongType = clientData;
    wrongType.type = 8;
    assert(!serverTransport.open((const uint8_t *)&wrongType,
                                 sizeof(wrongType), &packet[0], packet.size(), opened));
    packet[0] ^= 1;
    assert(!serverTransport.open((const uint8_t *)&clientData,
                                 sizeof(clientData), &packet[0], packet.size(), opened));

    std::cout << "OK: complete protocol v4 framing and encrypted transport test passed\n";
    return 0;
}
