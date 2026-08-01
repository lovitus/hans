#ifndef HANS_SECURE_H
#define HANS_SECURE_H

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

class SecureIdentity
{
public:
    SecureIdentity();
    ~SecureIdentity();

    void loadOrCreate(const std::string &path);
    const uint8_t *secretKey() const { return secret; }
    const uint8_t *publicKey() const { return publicValue; }
    std::string fingerprint() const;
    static std::string fingerprint(const uint8_t publicKey[32]);

private:
    uint8_t secret[32];
    uint8_t publicValue[32];
};

class NoiseHandshake
{
public:
    enum Role { INITIATOR, RESPONDER };

    NoiseHandshake(Role role, const uint8_t staticSecret[32],
                   const std::string &passphrase);
    NoiseHandshake(Role role, const uint8_t staticSecret[32],
                   const uint8_t precomputedPsk[32]);
    ~NoiseHandshake();

    bool writeMessage1(std::vector<uint8_t> &message);
    bool readMessage1(const uint8_t *message, size_t length);
    bool writeMessage2(std::vector<uint8_t> &message);
    bool readMessage2(const uint8_t *message, size_t length);
    bool writeMessage3(const uint8_t *payload, size_t payloadLength,
                       std::vector<uint8_t> &message);
    bool readMessage3(const uint8_t *message, size_t length,
                      std::vector<uint8_t> &payload);

    bool complete() const { return finished; }
    const uint8_t *sendKey() const;
    const uint8_t *receiveKey() const;
    const uint8_t *remoteStaticKey() const { return remoteStatic; }

    static void derivePsk(const std::string &passphrase, uint8_t psk[32]);

private:
    void construct(const uint8_t staticSecret[32]);
    void initialize();
    void generateEphemeral();
    void mixHash(const uint8_t *data, size_t length);
    void mixKey(const uint8_t *input, size_t length);
    void mixKeyAndHash(const uint8_t input[32]);
    bool dh(const uint8_t secretKey[32], const uint8_t publicKey[32]);
    void split();
    bool encryptAndHash(const uint8_t *plain, size_t length,
                        std::vector<uint8_t> &output);
    bool decryptAndHash(const uint8_t *cipher, size_t length,
                        std::vector<uint8_t> &output);

    Role role;
    int step;
    bool finished;
    bool hasKey;
    uint64_t nonce;
    uint8_t staticSecret[32];
    uint8_t staticPublic[32];
    uint8_t ephemeralSecret[32];
    uint8_t ephemeralPublic[32];
    uint8_t remoteEphemeral[32];
    uint8_t remoteStatic[32];
    uint8_t psk[32];
    uint8_t chainingKey[64];
    uint8_t handshakeHash[64];
    uint8_t cipherKey[32];
    uint8_t splitKeys[2][32];
};

class ReplayWindow64
{
public:
    ReplayWindow64();
    bool canAccept(uint64_t counter) const;
    void accept(uint64_t counter);

private:
    uint64_t largest;
    uint64_t received;
    bool initialized;
};

class SecureTransport
{
public:
    enum { PREFIX_SIZE = 12, TAG_SIZE = 16, OVERHEAD = 28 };

    SecureTransport();
    ~SecureTransport();
    void initialize(uint32_t sendIndex, uint32_t receiveIndex,
                    const uint8_t sendKey[32], const uint8_t receiveKey[32]);
    bool ready() const { return initialized; }
    uint32_t localIndex() const { return receiveIndex; }
    uint32_t peerIndex() const { return sendIndex; }
    bool seal(const uint8_t *additionalData, size_t additionalLength,
              const uint8_t *plain, size_t plainLength,
              std::vector<uint8_t> &packet);
    bool open(const uint8_t *additionalData, size_t additionalLength,
              const uint8_t *packet, size_t packetLength,
              std::vector<uint8_t> &plain);

private:
    bool initialized;
    uint32_t sendIndex;
    uint32_t receiveIndex;
    uint64_t sendCounter;
    uint8_t sendKeyValue[32];
    uint8_t receiveKeyValue[32];
    ReplayWindow64 replay;
};

#endif
