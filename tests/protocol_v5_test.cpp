#include "../src/secure.h"
#include "../src/transport.h"
#include "../third_party/monocypher/monocypher.h"

#include <assert.h>
#include <string.h>
#include <iostream>
#include <vector>

static void put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

int main()
{
    uint8_t psk[32], wrongPsk[32], envelopeKey[32], wrongKey[32];
    NoiseHandshake::derivePsk("protocol v5 integration", psk);
    NoiseHandshake::derivePsk("wrong protocol v5 integration", wrongPsk);
    HandshakeEnvelopeV5::deriveKey(psk, envelopeKey);
    HandshakeEnvelopeV5::deriveKey(wrongPsk, wrongKey);
    assert(crypto_verify32(envelopeKey, wrongKey) != 0);

    uint8_t clientSecret[32], serverSecret[32];
    for (int i = 0; i < 32; ++i)
    {
        clientSecret[i] = (uint8_t)(i + 1);
        serverSecret[i] = (uint8_t)(0xa0 + i);
    }
    NoiseHandshake client(NoiseHandshake::INITIATOR, clientSecret, psk);
    NoiseHandshake server(NoiseHandshake::RESPONDER, serverSecret, psk);

    std::vector<uint8_t> noise, wire, opened;
    assert(client.writeMessage1(noise) && noise.size() == 32);
    uint8_t init[40] = {0};
    init[0] = 1;
    init[1] = 7;
    put32(init + 4, 0x11223344);
    memcpy(init + 8, &noise[0], noise.size());
    assert(HandshakeEnvelopeV5::seal(envelopeKey, init, sizeof(init), wire));
    assert(wire.size() == HandshakeEnvelopeV5::OVERHEAD + sizeof(init));
    assert(memcmp(&wire[HandshakeEnvelopeV5::NONCE_SIZE], init,
                  sizeof(init)) != 0);
    assert(!HandshakeEnvelopeV5::open(wrongKey, &wire[0], wire.size(), opened));
    assert(HandshakeEnvelopeV5::open(envelopeKey, &wire[0], wire.size(), opened));
    assert(opened.size() == sizeof(init) &&
           memcmp(&opened[0], init, sizeof(init)) == 0);
    assert(server.readMessage1(&opened[8], 32));
    wire[wire.size() - 1] ^= 1;
    assert(!HandshakeEnvelopeV5::open(envelopeKey, &wire[0], wire.size(), opened));

    assert(server.writeMessage2(noise) && noise.size() == 96);
    std::vector<uint8_t> response(105);
    response[0] = 2;
    put32(&response[1], 0x55667788);
    put32(&response[5], 0x11223344);
    memcpy(&response[9], &noise[0], noise.size());
    assert(HandshakeEnvelopeV5::seal(envelopeKey, &response[0],
                                     response.size(), wire));
    assert(HandshakeEnvelopeV5::open(envelopeKey, &wire[0], wire.size(), opened));
    assert(opened[0] == 2 && client.readMessage2(&opened[9], 96));

    const uint8_t metadata[] = {1, 2, 3, 4, 5, 6};
    assert(client.writeMessage3(metadata, sizeof(metadata), noise));
    std::vector<uint8_t> finish(9 + noise.size());
    finish[0] = 3;
    put32(&finish[1], 0x11223344);
    put32(&finish[5], 0x55667788);
    memcpy(&finish[9], &noise[0], noise.size());
    assert(HandshakeEnvelopeV5::seal(envelopeKey, &finish[0], finish.size(), wire));
    assert(HandshakeEnvelopeV5::open(envelopeKey, &wire[0], wire.size(), opened));
    std::vector<uint8_t> decoded;
    assert(server.readMessage3(&opened[9], opened.size() - 9, decoded));
    assert(decoded.size() == sizeof(metadata) &&
           memcmp(&decoded[0], metadata, sizeof(metadata)) == 0);

    SecureTransport clientTransport, serverTransport;
    clientTransport.initialize(0x55667788, 0x11223344,
                               client.sendKey(), client.receiveKey());
    serverTransport.initialize(0x11223344, 0x55667788,
                               server.sendKey(), server.receiveKey());
    uint8_t plain[1 + TransportV3::HEADER_SIZE + 16] = {0};
    plain[0] = 7;
    TransportV3::Header transport;
    transport.mode = TransportV3::MODE_CREDIT;
    transport.sessionId = 0xabcdef01;
    transport.txSequence = 9;
    TransportV3::encode((char *)plain + 1, transport);
    for (size_t i = 1 + TransportV3::HEADER_SIZE; i < sizeof(plain); ++i)
        plain[i] = (uint8_t)i;
    const uint8_t clientAd[] = "Hans protocol v5 client data";
    const uint8_t serverAd[] = "Hans protocol v5 server data";
    assert(clientTransport.seal(clientAd, sizeof(clientAd) - 1,
                                plain, sizeof(plain), wire));
    assert(wire.size() == SecureTransport::OVERHEAD + sizeof(plain));
    assert(memcmp(&wire[SecureTransport::PREFIX_SIZE], plain,
                  sizeof(plain)) != 0);
    assert(!serverTransport.open(serverAd, sizeof(serverAd) - 1,
                                 &wire[0], wire.size(), opened));
    assert(serverTransport.open(clientAd, sizeof(clientAd) - 1,
                                &wire[0], wire.size(), opened));
    assert(opened.size() == sizeof(plain) && opened[0] == 7);
    assert(memcmp(&opened[0], plain, sizeof(plain)) == 0);
    assert(!serverTransport.open(clientAd, sizeof(clientAd) - 1,
                                 &wire[0], wire.size(), opened));

    crypto_wipe(psk, sizeof(psk));
    crypto_wipe(wrongPsk, sizeof(wrongPsk));
    crypto_wipe(envelopeKey, sizeof(envelopeKey));
    crypto_wipe(wrongKey, sizeof(wrongKey));
    std::cout << "OK: protocol v5 pre-auth handshake and full-field AEAD tests passed\n";
    return 0;
}
