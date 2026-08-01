#include "secure.h"
#include "utility.h"
#include "exception.h"
#include "../third_party/monocypher/monocypher.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <sstream>
#include <iomanip>

namespace
{
    const char PROTOCOL_NAME[] = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b";
    const uint8_t ARGON_SALT[16] = {
        'h','a','n','s','-','v','4','-','p','s','k','-','0','0','1','!'
    };

    void append(std::vector<uint8_t> &target, const uint8_t *data, size_t length)
    {
        target.insert(target.end(), data, data + length);
    }

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
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }

    void put64le(uint8_t *p, uint64_t value)
    {
        for (int i = 0; i < 8; ++i)
            p[i] = (uint8_t)(value >> (i * 8));
    }

    uint64_t get64le(const uint8_t *p)
    {
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
            value |= (uint64_t)p[i] << (i * 8);
        return value;
    }

    void hmacBlake2b(const uint8_t *key, size_t keyLength,
                     const uint8_t *data, size_t dataLength,
                     uint8_t output[64])
    {
        uint8_t normalized[128];
        uint8_t innerPad[128];
        uint8_t outerPad[128];
        uint8_t inner[64];
        memset(normalized, 0, sizeof(normalized));
        if (keyLength > 128)
        {
            crypto_blake2b(normalized, 64, key, keyLength);
            keyLength = 64;
        }
        else if (keyLength != 0)
            memcpy(normalized, key, keyLength);
        for (size_t i = 0; i < sizeof(innerPad); ++i)
        {
            uint8_t value = normalized[i];
            innerPad[i] = value ^ 0x36;
            outerPad[i] = value ^ 0x5c;
        }
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx, 64);
        crypto_blake2b_update(&ctx, innerPad, sizeof(innerPad));
        if (dataLength != 0)
            crypto_blake2b_update(&ctx, data, dataLength);
        crypto_blake2b_final(&ctx, inner);
        crypto_blake2b_init(&ctx, 64);
        crypto_blake2b_update(&ctx, outerPad, sizeof(outerPad));
        crypto_blake2b_update(&ctx, inner, sizeof(inner));
        crypto_blake2b_final(&ctx, output);
        crypto_wipe(normalized, sizeof(normalized));
        crypto_wipe(innerPad, sizeof(innerPad));
        crypto_wipe(outerPad, sizeof(outerPad));
        crypto_wipe(inner, sizeof(inner));
    }

    void hkdf(const uint8_t chainingKey[64], const uint8_t *input,
              size_t inputLength, uint8_t output1[64], uint8_t output2[64],
              uint8_t *output3)
    {
        uint8_t tempKey[64];
        uint8_t one = 1;
        hmacBlake2b(chainingKey, 64, input, inputLength, tempKey);
        hmacBlake2b(tempKey, 64, &one, 1, output1);
        uint8_t second[65];
        memcpy(second, output1, 64);
        second[64] = 2;
        hmacBlake2b(tempKey, 64, second, sizeof(second), output2);
        if (output3 != NULL)
        {
            uint8_t third[65];
            memcpy(third, output2, 64);
            third[64] = 3;
            hmacBlake2b(tempKey, 64, third, sizeof(third), output3);
            crypto_wipe(third, sizeof(third));
        }
        crypto_wipe(second, sizeof(second));
        crypto_wipe(tempKey, sizeof(tempKey));
    }

    void polyPad(crypto_poly1305_ctx *ctx, size_t length)
    {
        static const uint8_t zeros[16] = {0};
        size_t remainder = length & 15;
        if (remainder != 0)
            crypto_poly1305_update(ctx, zeros, 16 - remainder);
    }

    void chachaPolyTag(uint8_t tag[16], const uint8_t key[32],
                       uint64_t counter, const uint8_t *ad, size_t adLength,
                       const uint8_t *cipher, size_t cipherLength)
    {
        uint8_t nonce[12] = {0};
        uint8_t polyKey[32] = {0};
        uint8_t lengths[16];
        put64le(nonce + 4, counter);
        crypto_chacha20_ietf(polyKey, polyKey, sizeof(polyKey), key, nonce, 0);
        put64le(lengths, adLength);
        put64le(lengths + 8, cipherLength);
        crypto_poly1305_ctx ctx;
        crypto_poly1305_init(&ctx, polyKey);
        if (adLength != 0)
            crypto_poly1305_update(&ctx, ad, adLength);
        polyPad(&ctx, adLength);
        if (cipherLength != 0)
            crypto_poly1305_update(&ctx, cipher, cipherLength);
        polyPad(&ctx, cipherLength);
        crypto_poly1305_update(&ctx, lengths, sizeof(lengths));
        crypto_poly1305_final(&ctx, tag);
        crypto_wipe(polyKey, sizeof(polyKey));
    }

    void chachaPolyLock(uint8_t *cipher, uint8_t tag[16], const uint8_t key[32],
                        uint64_t counter, const uint8_t *ad, size_t adLength,
                        const uint8_t *plain, size_t plainLength)
    {
        uint8_t nonce[12] = {0};
        put64le(nonce + 4, counter);
        if (plainLength != 0)
            crypto_chacha20_ietf(cipher, plain, plainLength, key, nonce, 1);
        chachaPolyTag(tag, key, counter, ad, adLength, cipher, plainLength);
    }

    bool chachaPolyUnlock(uint8_t *plain, const uint8_t tag[16],
                          const uint8_t key[32], uint64_t counter,
                          const uint8_t *ad, size_t adLength,
                          const uint8_t *cipher, size_t cipherLength)
    {
        uint8_t expected[16];
        chachaPolyTag(expected, key, counter, ad, adLength,
                      cipher, cipherLength);
        if (crypto_verify16(tag, expected) != 0)
            return false;
        uint8_t nonce[12] = {0};
        put64le(nonce + 4, counter);
        if (cipherLength != 0)
            crypto_chacha20_ietf(plain, cipher, cipherLength, key, nonce, 1);
        return true;
    }

    bool readExact(int fd, uint8_t *data, size_t length)
    {
        size_t offset = 0;
        while (offset < length)
        {
            ssize_t count = read(fd, data + offset, length - offset);
            if (count > 0)
                offset += (size_t)count;
            else if (count < 0 && errno == EINTR)
                continue;
            else
                return false;
        }
        return true;
    }
}

SecureIdentity::SecureIdentity()
{
    memset(secret, 0, sizeof(secret));
    memset(publicValue, 0, sizeof(publicValue));
}

SecureIdentity::~SecureIdentity()
{
    crypto_wipe(secret, sizeof(secret));
}

void SecureIdentity::loadOrCreate(const std::string &path)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd >= 0)
    {
        bool ok = readExact(fd, secret, sizeof(secret));
        uint8_t extra;
        bool exact = ok && read(fd, &extra, 1) == 0;
        close(fd);
        if (!exact)
            throw Exception("invalid secure identity file");
    }
    else
    {
        if (errno != ENOENT)
            throw Exception("could not open secure identity file", true);
        Utility::ensureParentDirectory(path);
        Utility::secureRandom(secret, sizeof(secret));
        fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            throw Exception("could not create secure identity file", true);
        size_t offset = 0;
        while (offset < sizeof(secret))
        {
            ssize_t count = write(fd, secret + offset, sizeof(secret) - offset);
            if (count > 0)
                offset += (size_t)count;
            else if (count < 0 && errno == EINTR)
                continue;
            else
            {
                int saved = errno;
                close(fd);
                errno = saved;
                throw Exception("could not write secure identity file", true);
            }
        }
        fsync(fd);
        close(fd);
    }
    crypto_x25519_public_key(publicValue, secret);
}

std::string SecureIdentity::fingerprint() const
{
    return fingerprint(publicValue);
}

std::string SecureIdentity::fingerprint(const uint8_t publicKey[32])
{
    uint8_t digest[16];
    crypto_blake2b(digest, sizeof(digest), publicKey, 32);
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (size_t i = 0; i < sizeof(digest); ++i)
        output << std::setw(2) << (unsigned int)digest[i];
    return output.str();
}

NoiseHandshake::NoiseHandshake(Role role, const uint8_t secretKey[32],
                               const std::string &passphrase)
    : role(role), step(0), finished(false), hasKey(false), nonce(0)
{
    derivePsk(passphrase, psk);
    construct(secretKey);
}

NoiseHandshake::NoiseHandshake(Role role, const uint8_t secretKey[32],
                               const uint8_t precomputedPsk[32])
    : role(role), step(0), finished(false), hasKey(false), nonce(0)
{
    memcpy(psk, precomputedPsk, 32);
    construct(secretKey);
}

void NoiseHandshake::construct(const uint8_t secretKey[32])
{
    memcpy(staticSecret, secretKey, 32);
    crypto_x25519_public_key(staticPublic, staticSecret);
    memset(ephemeralSecret, 0, 32);
    memset(ephemeralPublic, 0, 32);
    memset(remoteEphemeral, 0, 32);
    memset(remoteStatic, 0, 32);
    memset(splitKeys, 0, sizeof(splitKeys));
    initialize();
}

NoiseHandshake::~NoiseHandshake()
{
    crypto_wipe(staticSecret, sizeof(staticSecret));
    crypto_wipe(ephemeralSecret, sizeof(ephemeralSecret));
    crypto_wipe(psk, sizeof(psk));
    crypto_wipe(chainingKey, sizeof(chainingKey));
    crypto_wipe(cipherKey, sizeof(cipherKey));
    crypto_wipe(splitKeys, sizeof(splitKeys));
}

void NoiseHandshake::derivePsk(const std::string &passphrase, uint8_t output[32])
{
    const uint32_t blocks = 8192;
    void *work = new uint8_t[(size_t)blocks * 1024];
    crypto_argon2_config config = { CRYPTO_ARGON2_ID, blocks, 3, 1 };
    crypto_argon2_inputs inputs = {
        (const uint8_t *)passphrase.data(), ARGON_SALT,
        (uint32_t)passphrase.size(), sizeof(ARGON_SALT)
    };
    crypto_argon2(output, 32, work, config, inputs, crypto_argon2_no_extras);
    crypto_wipe(work, (size_t)blocks * 1024);
    delete [] (uint8_t *)work;
}

void NoiseHandshake::initialize()
{
    size_t nameLength = strlen(PROTOCOL_NAME);
    if (nameLength <= 64)
    {
        memset(handshakeHash, 0, 64);
        memcpy(handshakeHash, PROTOCOL_NAME, nameLength);
    }
    else
        crypto_blake2b(handshakeHash, 64, (const uint8_t *)PROTOCOL_NAME,
                       nameLength);
    memcpy(chainingKey, handshakeHash, 64);
    memset(cipherKey, 0, 32);
}

void NoiseHandshake::generateEphemeral()
{
    Utility::secureRandom(ephemeralSecret, 32);
    crypto_x25519_public_key(ephemeralPublic, ephemeralSecret);
}

void NoiseHandshake::mixHash(const uint8_t *data, size_t length)
{
    crypto_blake2b_ctx ctx;
    uint8_t result[64];
    crypto_blake2b_init(&ctx, 64);
    crypto_blake2b_update(&ctx, handshakeHash, 64);
    if (length != 0)
        crypto_blake2b_update(&ctx, data, length);
    crypto_blake2b_final(&ctx, result);
    memcpy(handshakeHash, result, 64);
}

void NoiseHandshake::mixKey(const uint8_t *input, size_t length)
{
    uint8_t nextCk[64], nextKey[64];
    hkdf(chainingKey, input, length, nextCk, nextKey, NULL);
    memcpy(chainingKey, nextCk, 64);
    memcpy(cipherKey, nextKey, 32);
    hasKey = true;
    nonce = 0;
    crypto_wipe(nextCk, sizeof(nextCk));
    crypto_wipe(nextKey, sizeof(nextKey));
}

void NoiseHandshake::mixKeyAndHash(const uint8_t input[32])
{
    uint8_t nextCk[64], tempHash[64], nextKey[64];
    hkdf(chainingKey, input, 32, nextCk, tempHash, nextKey);
    memcpy(chainingKey, nextCk, 64);
    mixHash(tempHash, 64);
    memcpy(cipherKey, nextKey, 32);
    hasKey = true;
    nonce = 0;
    crypto_wipe(nextCk, sizeof(nextCk));
    crypto_wipe(tempHash, sizeof(tempHash));
    crypto_wipe(nextKey, sizeof(nextKey));
}

bool NoiseHandshake::dh(const uint8_t secretKey[32], const uint8_t publicKey[32])
{
    uint8_t shared[32];
    uint8_t any = 0;
    crypto_x25519(shared, secretKey, publicKey);
    for (size_t i = 0; i < sizeof(shared); ++i)
        any |= shared[i];
    if (any != 0)
        mixKey(shared, sizeof(shared));
    crypto_wipe(shared, sizeof(shared));
    return any != 0;
}

bool NoiseHandshake::encryptAndHash(const uint8_t *plain, size_t length,
                                    std::vector<uint8_t> &output)
{
    size_t start = output.size();
    if (!hasKey)
    {
        append(output, plain, length);
        mixHash(plain, length);
        return true;
    }
    output.resize(start + length + 16);
    chachaPolyLock(&output[start], &output[start + length], cipherKey, nonce,
                   handshakeHash, 64, plain, length);
    nonce++;
    mixHash(&output[start], length + 16);
    return true;
}

bool NoiseHandshake::decryptAndHash(const uint8_t *cipher, size_t length,
                                    std::vector<uint8_t> &output)
{
    if (!hasKey)
    {
        output.assign(cipher, cipher + length);
        mixHash(cipher, length);
        return true;
    }
    if (length < 16)
        return false;
    size_t plainLength = length - 16;
    output.resize(plainLength);
    if (!chachaPolyUnlock(plainLength == 0 ? NULL : &output[0],
                          cipher + plainLength, cipherKey, nonce,
                          handshakeHash, 64, cipher, plainLength))
        return false;
    nonce++;
    mixHash(cipher, length);
    return true;
}

bool NoiseHandshake::writeMessage1(std::vector<uint8_t> &message)
{
    if (role != INITIATOR || step != 0)
        return false;
    generateEphemeral();
    message.assign(ephemeralPublic, ephemeralPublic + 32);
    mixHash(ephemeralPublic, 32);
    step = 1;
    return true;
}

bool NoiseHandshake::readMessage1(const uint8_t *message, size_t length)
{
    if (role != RESPONDER || step != 0 || length != 32)
        return false;
    memcpy(remoteEphemeral, message, 32);
    mixHash(remoteEphemeral, 32);
    step = 1;
    return true;
}

bool NoiseHandshake::writeMessage2(std::vector<uint8_t> &message)
{
    if (role != RESPONDER || step != 1)
        return false;
    generateEphemeral();
    message.assign(ephemeralPublic, ephemeralPublic + 32);
    mixHash(ephemeralPublic, 32);
    if (!dh(ephemeralSecret, remoteEphemeral))
        return false;
    if (!encryptAndHash(staticPublic, 32, message))
        return false;
    if (!dh(staticSecret, remoteEphemeral))
        return false;
    if (!encryptAndHash(NULL, 0, message))
        return false;
    step = 2;
    return true;
}

bool NoiseHandshake::readMessage2(const uint8_t *message, size_t length)
{
    if (role != INITIATOR || step != 1 || length != 96)
        return false;
    memcpy(remoteEphemeral, message, 32);
    mixHash(remoteEphemeral, 32);
    if (!dh(ephemeralSecret, remoteEphemeral))
        return false;
    std::vector<uint8_t> decoded;
    if (!decryptAndHash(message + 32, 48, decoded) || decoded.size() != 32)
        return false;
    memcpy(remoteStatic, &decoded[0], 32);
    if (!dh(ephemeralSecret, remoteStatic))
        return false;
    if (!decryptAndHash(message + 80, 16, decoded) || !decoded.empty())
        return false;
    step = 2;
    return true;
}

bool NoiseHandshake::writeMessage3(const uint8_t *payload, size_t payloadLength,
                                   std::vector<uint8_t> &message)
{
    if (role != INITIATOR || step != 2)
        return false;
    message.clear();
    if (!encryptAndHash(staticPublic, 32, message))
        return false;
    if (!dh(staticSecret, remoteEphemeral))
        return false;
    mixKeyAndHash(psk);
    if (!encryptAndHash(payload, payloadLength, message))
        return false;
    split();
    step = 3;
    finished = true;
    return true;
}

bool NoiseHandshake::readMessage3(const uint8_t *message, size_t length,
                                  std::vector<uint8_t> &payload)
{
    if (role != RESPONDER || step != 2 || length < 64)
        return false;
    std::vector<uint8_t> decoded;
    if (!decryptAndHash(message, 48, decoded) || decoded.size() != 32)
        return false;
    memcpy(remoteStatic, &decoded[0], 32);
    if (!dh(ephemeralSecret, remoteStatic))
        return false;
    mixKeyAndHash(psk);
    if (!decryptAndHash(message + 48, length - 48, payload))
        return false;
    split();
    step = 3;
    finished = true;
    return true;
}

void NoiseHandshake::split()
{
    uint8_t first[64], second[64];
    hkdf(chainingKey, NULL, 0, first, second, NULL);
    memcpy(splitKeys[0], first, 32);
    memcpy(splitKeys[1], second, 32);
    crypto_wipe(first, sizeof(first));
    crypto_wipe(second, sizeof(second));
}

const uint8_t *NoiseHandshake::sendKey() const
{
    return role == INITIATOR ? splitKeys[0] : splitKeys[1];
}

const uint8_t *NoiseHandshake::receiveKey() const
{
    return role == INITIATOR ? splitKeys[1] : splitKeys[0];
}

ReplayWindow64::ReplayWindow64() : largest(0), received(0), initialized(false) { }

bool ReplayWindow64::canAccept(uint64_t counter) const
{
    if (!initialized || counter > largest)
        return true;
    uint64_t distance = largest - counter;
    return distance < 64 && (received & ((uint64_t)1 << distance)) == 0;
}

void ReplayWindow64::accept(uint64_t counter)
{
    if (!initialized)
    {
        initialized = true;
        largest = counter;
        received = 1;
    }
    else if (counter > largest)
    {
        uint64_t distance = counter - largest;
        received = distance >= 64 ? 1 : (received << distance) | 1;
        largest = counter;
    }
    else
        received |= (uint64_t)1 << (largest - counter);
}

SecureTransport::SecureTransport()
    : initialized(false), sendIndex(0), receiveIndex(0), sendCounter(0)
{
    memset(sendKeyValue, 0, 32);
    memset(receiveKeyValue, 0, 32);
}

SecureTransport::~SecureTransport()
{
    crypto_wipe(sendKeyValue, sizeof(sendKeyValue));
    crypto_wipe(receiveKeyValue, sizeof(receiveKeyValue));
}

void SecureTransport::initialize(uint32_t peer, uint32_t local,
                                 const uint8_t sendKey[32],
                                 const uint8_t receiveKey[32])
{
    sendIndex = peer;
    receiveIndex = local;
    memcpy(sendKeyValue, sendKey, 32);
    memcpy(receiveKeyValue, receiveKey, 32);
    sendCounter = 0;
    replay = ReplayWindow64();
    initialized = true;
}

bool SecureTransport::seal(const uint8_t *ad, size_t adLength,
                           const uint8_t *plain, size_t plainLength,
                           std::vector<uint8_t> &packet)
{
    if (!initialized || sendCounter == ~(uint64_t)0)
        return false;
    packet.resize(OVERHEAD + plainLength);
    put32(&packet[0], sendIndex);
    put64le(&packet[4], sendCounter);
    chachaPolyLock(&packet[PREFIX_SIZE], &packet[PREFIX_SIZE + plainLength],
                   sendKeyValue, sendCounter, ad, adLength, plain, plainLength);
    sendCounter++;
    return true;
}

bool SecureTransport::open(const uint8_t *ad, size_t adLength,
                           const uint8_t *packet, size_t packetLength,
                           std::vector<uint8_t> &plain)
{
    if (!initialized || packetLength < OVERHEAD ||
        get32(packet) != receiveIndex)
        return false;
    uint64_t counter = get64le(packet + 4);
    if (!replay.canAccept(counter))
        return false;
    size_t plainLength = packetLength - OVERHEAD;
    plain.resize(plainLength);
    if (!chachaPolyUnlock(plainLength == 0 ? NULL : &plain[0],
                          packet + PREFIX_SIZE + plainLength,
                          receiveKeyValue, counter, ad, adLength,
                          packet + PREFIX_SIZE, plainLength))
        return false;
    replay.accept(counter);
    return true;
}
