#include "../src/secure.h"
#include "../third_party/monocypher/monocypher.h"

#include <assert.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <time.h>

static void exchange(NoiseHandshake &initiator, NoiseHandshake &responder,
                     const char *payload)
{
    std::vector<uint8_t> message;
    std::vector<uint8_t> decoded;
    assert(initiator.writeMessage1(message));
    assert(message.size() == 32);
    assert(responder.readMessage1(&message[0], message.size()));
    assert(responder.writeMessage2(message));
    assert(message.size() == 96);
    assert(initiator.readMessage2(&message[0], message.size()));
    assert(initiator.writeMessage3((const uint8_t *)payload, strlen(payload), message));
    assert(responder.readMessage3(&message[0], message.size(), decoded));
    assert(decoded.size() == strlen(payload));
    assert(memcmp(&decoded[0], payload, decoded.size()) == 0);
    assert(initiator.complete() && responder.complete());
    assert(crypto_verify32(initiator.sendKey(), responder.receiveKey()) == 0);
    assert(crypto_verify32(initiator.receiveKey(), responder.sendKey()) == 0);
}

static void testHandshakeAndTransport()
{
    uint8_t clientSecret[32];
    uint8_t serverSecret[32];
    for (int i = 0; i < 32; ++i)
    {
        clientSecret[i] = (uint8_t)(i + 1);
        serverSecret[i] = (uint8_t)(0xa0 + i);
    }
    uint8_t clientPublic[32], serverPublic[32];
    crypto_x25519_public_key(clientPublic, clientSecret);
    crypto_x25519_public_key(serverPublic, serverSecret);
    assert(SecureIdentity::fingerprint(clientPublic).size() == 32);

    NoiseHandshake client(NoiseHandshake::INITIATOR, clientSecret, "test passphrase");
    NoiseHandshake server(NoiseHandshake::RESPONDER, serverSecret, "test passphrase");
    exchange(client, server, "encrypted connect metadata");
    assert(crypto_verify32(client.remoteStaticKey(), serverPublic) == 0);
    assert(crypto_verify32(server.remoteStaticKey(), clientPublic) == 0);

    SecureTransport clientTransport, serverTransport;
    clientTransport.initialize(0x22222222, 0x11111111,
                               client.sendKey(), client.receiveKey());
    serverTransport.initialize(0x11111111, 0x22222222,
                               server.sendKey(), server.receiveKey());
    const uint8_t ad[] = {'h','n','c','4',7};
    const char plainText[] = "authenticated tunnel packet";
    std::vector<uint8_t> packet, opened;
    assert(clientTransport.seal(ad, sizeof(ad), (const uint8_t *)plainText,
                                sizeof(plainText), packet));
    assert(serverTransport.open(ad, sizeof(ad), &packet[0], packet.size(), opened));
    assert(opened.size() == sizeof(plainText));
    assert(memcmp(&opened[0], plainText, sizeof(plainText)) == 0);
    assert(!serverTransport.open(ad, sizeof(ad), &packet[0], packet.size(), opened));

    assert(serverTransport.seal(ad, sizeof(ad), (const uint8_t *)plainText,
                                sizeof(plainText), packet));
    packet[SecureTransport::PREFIX_SIZE] ^= 1;
    assert(!clientTransport.open(ad, sizeof(ad), &packet[0], packet.size(), opened));
}

static void testWrongPskAndTamper()
{
    uint8_t clientSecret[32] = {1};
    uint8_t serverSecret[32] = {2};
    NoiseHandshake client(NoiseHandshake::INITIATOR, clientSecret, "right");
    NoiseHandshake server(NoiseHandshake::RESPONDER, serverSecret, "wrong");
    std::vector<uint8_t> message, payload;
    assert(client.writeMessage1(message));
    assert(server.readMessage1(&message[0], message.size()));
    assert(server.writeMessage2(message));
    assert(client.readMessage2(&message[0], message.size()));
    assert(client.writeMessage3(NULL, 0, message));
    assert(!server.readMessage3(&message[0], message.size(), payload));

    NoiseHandshake client2(NoiseHandshake::INITIATOR, clientSecret, "same");
    NoiseHandshake server2(NoiseHandshake::RESPONDER, serverSecret, "same");
    assert(client2.writeMessage1(message));
    assert(server2.readMessage1(&message[0], message.size()));
    assert(server2.writeMessage2(message));
    message[40] ^= 1;
    assert(!client2.readMessage2(&message[0], message.size()));
}

static void testIdentityFilePermissions()
{
    char path[128];
    snprintf(path, sizeof(path), "/tmp/hans-secure-test-%ld-%u",
             (long)getpid(), (unsigned int)time(NULL));
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    uint8_t key[32] = {7};
    assert(write(fd, key, sizeof(key)) == (ssize_t)sizeof(key));
    close(fd);
    assert(chmod(path, 0644) == 0);
    bool rejected = false;
    try
    {
        SecureIdentity identity;
        identity.loadOrCreate(path);
    }
    catch (...)
    {
        rejected = true;
    }
    assert(rejected);
    unlink(path);
}

int main()
{
    testHandshakeAndTransport();
    testWrongPskAndTamper();
    testIdentityFilePermissions();
    std::cout << "OK: Noise XXpsk3 handshake, AEAD and replay tests passed\n";
    return 0;
}
