/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2009 Friedrich Schöller <hans@schoeller.se>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "client.h"
#include "server.h"
#include "exception.h"
#include "config.h"
#include "utility.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <algorithm>

using std::vector;
using std::string;

const Worker::TunnelHeader::Magic Client::magic("hanc");
const Worker::TunnelHeader::Magic Client::v2Magic("hnc2");
const Worker::TunnelHeader::Magic Client::v3Magic("hnc3");
const Worker::TunnelHeader::Magic Client::v4Magic("hnc4");

namespace
{
    const int AUTO_POLL_FALLBACK = 10;
    const int TRANSPORT_TICK_MS = 250;
    const int DIRECT_PROBE_TIMEOUT_MS = 2000;
    const int DIRECT_REPROBE_INTERVAL_MS = 30000;
    const int DIRECT_HEARTBEAT_MS = 1000;
    const int DIRECT_WATCHDOG_MS = 5000;
    const int V4_CREDIT_HEARTBEAT_MS = 5000;
    const int V4_SESSION_TIMEOUT_MS = 20000;
    const int V4_RECONNECT_JITTER_MS = 2000;
    const uint8_t V5_HANDSHAKE_INIT = 1;
    const uint8_t V5_HANDSHAKE_RESPONSE = 2;
    const uint8_t V5_HANDSHAKE_FINISH = 3;
    const uint8_t V5_CLIENT_DATA_AD[] = "Hans protocol v5 client data";
    const uint8_t V5_SERVER_DATA_AD[] = "Hans protocol v5 server data";
    uint32_t get32(const char *buffer)
    {
        uint32_t value;
        memcpy(&value, buffer, sizeof(value));
        return ntohl(value);
    }
    void put32(char *buffer, uint32_t value)
    {
        value = htonl(value);
        memcpy(buffer, &value, sizeof(value));
    }
    void put16(char *buffer, uint16_t value)
    {
        value = htons(value);
        memcpy(buffer, &value, sizeof(value));
    }
}

Client::Client(int tunnelMtu, const string *deviceName,
               const Echo::Address &serverAddress,
               int maxPolls, const string &passphrase, uid_t uid, gid_t gid,
               bool changeEchoId, bool changeEchoSeq, uint32_t desiredIp,
               const string &deviceId, bool userspace,
               const string &socksAddress,
               const vector<SharePort> &sharePorts,
               bool allPorts,
               const string &identityFile, bool requireV4, bool requireV5,
               const string &serverFingerprint, const string &socksUser,
               const string &socksPassword)
    : Worker(tunnelMtu, deviceName, false, uid, gid, !userspace, userspace),
      auth(passphrase)
{
    this->serverAddress = serverAddress;
    this->clientIp = INADDR_NONE;
    this->desiredIp = desiredIp;
    this->autoPoll = maxPolls < 0;
    this->maxPolls = autoPoll ? 4 : maxPolls;
    this->nextEchoId = Utility::rand();
    this->changeEchoId = changeEchoId;
    this->changeEchoSeq = changeEchoSeq;
    this->nextEchoSequence = Utility::rand();
    this->deviceId = deviceId;
    this->protocolVersion = 5;
    this->protocolRequestAttempts = 0;
    this->requireV4 = requireV4;
    this->requireV5 = requireV5;
    this->expectedServerFingerprint = serverFingerprint;
    this->negotiatedCapabilities = 0;
    this->sessionId = 0;
    this->localReceiverIndex = 0;
    this->peerReceiverIndex = 0;
    this->secureHandshake = NULL;
    secureIdentity.loadOrCreate(identityFile.empty() ?
                                Utility::defaultStateFile("identity.key") :
                                identityFile);
    NoiseHandshake::derivePsk(passphrase, securePsk);
    HandshakeEnvelopeV5::deriveKey(securePsk, handshakeKeyV5);
    this->nextTransportSequence = Utility::random32();
    this->lastUnauthenticatedWarning = Time::ZERO;
    this->transportMode = TransportV3::MODE_CREDIT;
    this->peerTransportMode = TransportV3::MODE_CREDIT;
    this->directProbePending = false;
    this->directProbeReplies = 0;
    this->userspaceNetwork = userspace ?
        new UserspaceNetwork(this, tunnelMtu, socksAddress, sharePorts,
                             allPorts, socksUser, socksPassword) : NULL;
#ifdef WIN32
    if (userspace)
    {
        // IcmpSendEcho2 requests have a finite lifetime.  Bound the adaptive
        // credit window so a full replacement window can be issued before
        // the previous one expires, leaving no idle receive gap.
        adaptiveCredit = AdaptiveCredit(2, WINDOWS_ICMP_MAX_CREDITS, 4);
    }
#endif

    state = STATE_CLOSED;
}

Client::~Client()
{
    delete secureHandshake;
    memset(securePsk, 0, sizeof(securePsk));
    memset(handshakeKeyV5, 0, sizeof(handshakeKeyV5));
    delete userspaceNetwork;
}

void Client::sendConnectionRequest()
{
    if (protocolRequestAttempts >= 2 && protocolVersion > 1)
    {
        if (protocolVersion == 5 && requireV5)
            throw Exception("secure protocol v5 handshake timed out; refusing downgrade");
        if (protocolVersion == 4 && requireV4)
            throw Exception("secure protocol v4 handshake timed out; refusing downgrade");
        protocolVersion--;
        protocolRequestAttempts = 0;
        syslog(LOG_WARNING, "server did not answer protocol v%d handshake; falling back to v%d",
               protocolVersion + 1, protocolVersion);
    }

    syslog(LOG_DEBUG, "sending protocol v%d connection request", protocolVersion);

    if (protocolVersion == 5)
    {
        delete secureHandshake;
        secureHandshake = new NoiseHandshake(NoiseHandshake::INITIATOR,
                                              secureIdentity.secretKey(),
                                              securePsk);
        do localReceiverIndex = Utility::random32(); while (localReceiverIndex == 0);
        peerReceiverIndex = 0;
        std::vector<uint8_t> message;
        if (!secureHandshake->writeMessage1(message))
            throw Exception("creating secure handshake initiation");
        uint8_t plain[40];
        memset(plain, 0, sizeof(plain));
        plain[0] = V5_HANDSHAKE_INIT;
#ifdef WIN32
        if (userspaceNetwork != NULL)
            plain[1] |= TransportV3::CAP_WINDOWS_ICMP_HELPER;
#endif
        put32((char *)plain + 4, localReceiverIndex);
        memcpy(plain + 8, &message[0], message.size());
        std::vector<uint8_t> envelope;
        HandshakeEnvelopeV5::seal(handshakeKeyV5, plain, sizeof(plain),
                                  envelope);
        sendRawEchoToServer(&envelope[0], (int)envelope.size());
    }
    else if (protocolVersion == 4)
    {
        delete secureHandshake;
        secureHandshake = new NoiseHandshake(NoiseHandshake::INITIATOR,
                                              secureIdentity.secretKey(),
                                              securePsk);
        localReceiverIndex = Utility::random32();
        peerReceiverIndex = 0;
        std::vector<uint8_t> message;
        if (!secureHandshake->writeMessage1(message))
            throw Exception("creating secure handshake initiation");
        put32(echoSendPayloadBuffer(), localReceiverIndex);
        uint8_t handshakeHints = 0;
#ifdef WIN32
        if (userspaceNetwork != NULL)
            handshakeHints |= TransportV3::CAP_WINDOWS_ICMP_HELPER;
#endif
        echoSendPayloadBuffer()[4] = (char)handshakeHints;
        memcpy(echoSendPayloadBuffer() + 5, &message[0], message.size());
        sendEchoToServer(TunnelHeader::TYPE_HANDSHAKE_INIT,
                         5 + (int)message.size());
    }
    else if (protocolVersion == 1)
    {
        Server::ClientConnectData *connectData =
            (Server::ClientConnectData *)echoSendPayloadBuffer();
        memset(connectData, 0, sizeof(*connectData));
        connectData->maxPolls = autoPoll ? AUTO_POLL_FALLBACK : maxPolls;
        connectData->desiredIp = desiredIp;
        sendEchoToServer(TunnelHeader::TYPE_CONNECTION_REQUEST,
                         sizeof(Server::ClientConnectData));
    }
    else if (protocolVersion == 2)
    {
        Server::ClientConnectDataV2 *connectData =
            (Server::ClientConnectDataV2 *)echoSendPayloadBuffer();
        memset(connectData, 0, sizeof(*connectData));
        connectData->legacy.maxPolls = autoPoll ? AUTO_POLL_FALLBACK : maxPolls;
        connectData->legacy.desiredIp = desiredIp;
        memcpy(connectData->deviceId, deviceId.data(), DEVICE_ID_HEX_SIZE);
        sendEchoToServer(TunnelHeader::TYPE_CONNECTION_REQUEST,
                         sizeof(Server::ClientConnectDataV2));
    }
    else
    {
        Server::ClientConnectDataV3 *connectData =
            (Server::ClientConnectDataV3 *)echoSendPayloadBuffer();
        memset(connectData, 0, sizeof(*connectData));
        connectData->v2.legacy.maxPolls = autoPoll ? adaptiveCredit.target() : maxPolls;
        connectData->v2.legacy.desiredIp = desiredIp;
        memcpy(connectData->v2.deviceId, deviceId.data(), DEVICE_ID_HEX_SIZE);
        bool windowsIcmpHelper = false;
#ifdef WIN32
        windowsIcmpHelper = userspaceNetwork != NULL;
#endif
        connectData->capabilities = TransportV3::advertisedCapabilities(
            autoPoll, windowsIcmpHelper);
        connectData->minimumPolls = 2;
        connectData->maximumPolls = 128;
        sendEchoToServer(TunnelHeader::TYPE_CONNECTION_REQUEST,
                         sizeof(Server::ClientConnectDataV3));
    }

    protocolRequestAttempts++;

    state = STATE_CONNECTION_REQUEST_SENT;
    setTimeout(5000);
}

void Client::sendRawEchoToServer(const uint8_t *packet, int length)
{
    if (length < 0 || length > rawPayloadBufferSize())
        throw Exception("packet too big");
    if (length > 0)
        memcpy(rawEchoSendPayloadBuffer(), packet, length);
    sendRawEcho(length, serverAddress, false, nextEchoId, nextEchoSequence);
    if (changeEchoId)
        nextEchoId = nextEchoId + 38543;
    if (changeEchoSeq)
        nextEchoSequence = nextEchoSequence + 38543;
}

void Client::sendV4HandshakeFinish()
{
    Server::ClientConnectDataV3 connectData;
    memset(&connectData, 0, sizeof(connectData));
    connectData.v2.legacy.maxPolls = autoPoll ? adaptiveCredit.target() : maxPolls;
    connectData.v2.legacy.desiredIp = desiredIp;
    memcpy(connectData.v2.deviceId, deviceId.data(), DEVICE_ID_HEX_SIZE);
    bool windowsIcmpHelper = false;
#ifdef WIN32
    windowsIcmpHelper = userspaceNetwork != NULL;
#endif
    connectData.capabilities = TransportV3::advertisedCapabilities(
        autoPoll, windowsIcmpHelper);
    connectData.minimumPolls = 2;
    connectData.maximumPolls = 128;
    uint8_t metadata[sizeof(connectData) + 2];
    memcpy(metadata, &connectData, sizeof(connectData));
    put16((char *)metadata + sizeof(connectData), (uint16_t)tunnelMtu);
    std::vector<uint8_t> message;
    if (secureHandshake == NULL ||
        !secureHandshake->writeMessage3(metadata, sizeof(metadata), message))
        throw Exception("creating secure handshake finish");
    secureTransport.initialize(peerReceiverIndex, localReceiverIndex,
                               secureHandshake->sendKey(),
                               secureHandshake->receiveKey());
    put32(echoSendPayloadBuffer(), localReceiverIndex);
    put32(echoSendPayloadBuffer() + 4, peerReceiverIndex);
    memcpy(echoSendPayloadBuffer() + 8, &message[0], message.size());
    sendEchoToServer(TunnelHeader::TYPE_HANDSHAKE_FINISH,
                     8 + (int)message.size());
    state = STATE_CHALLENGE_RESPONSE_SENT;
    setTimeout(5000);
}

void Client::sendV5HandshakeFinish()
{
    Server::ClientConnectDataV3 connectData;
    memset(&connectData, 0, sizeof(connectData));
    connectData.v2.legacy.maxPolls = autoPoll ? adaptiveCredit.target() : maxPolls;
    connectData.v2.legacy.desiredIp = desiredIp;
    memcpy(connectData.v2.deviceId, deviceId.data(), DEVICE_ID_HEX_SIZE);
    bool windowsIcmpHelper = false;
#ifdef WIN32
    windowsIcmpHelper = userspaceNetwork != NULL;
#endif
    connectData.capabilities = TransportV3::advertisedCapabilities(
        autoPoll, windowsIcmpHelper);
    connectData.minimumPolls = 2;
    connectData.maximumPolls = 128;
    uint8_t metadata[sizeof(connectData) + 2];
    memcpy(metadata, &connectData, sizeof(connectData));
    put16((char *)metadata + sizeof(connectData), (uint16_t)tunnelMtu);
    std::vector<uint8_t> message;
    if (secureHandshake == NULL ||
        !secureHandshake->writeMessage3(metadata, sizeof(metadata), message))
        throw Exception("creating secure handshake finish");
    secureTransport.initialize(peerReceiverIndex, localReceiverIndex,
                               secureHandshake->sendKey(),
                               secureHandshake->receiveKey());
    std::vector<uint8_t> plain(9 + message.size());
    plain[0] = V5_HANDSHAKE_FINISH;
    put32((char *)&plain[1], localReceiverIndex);
    put32((char *)&plain[5], peerReceiverIndex);
    memcpy(&plain[9], &message[0], message.size());
    std::vector<uint8_t> envelope;
    HandshakeEnvelopeV5::seal(handshakeKeyV5, &plain[0], plain.size(), envelope);
    sendRawEchoToServer(&envelope[0], (int)envelope.size());
    state = STATE_CHALLENGE_RESPONSE_SENT;
    setTimeout(5000);
}

void Client::sendChallengeResponse(int dataLength)
{
    if (dataLength != CHALLENGE_SIZE)
        throw Exception("invalid challenge received");

    state = STATE_CHALLENGE_RESPONSE_SENT;

    syslog(LOG_DEBUG, "sending challenge response");

    vector<char> challenge;
    challenge.resize(dataLength);
    memcpy(&challenge[0], echoReceivePayloadBuffer(), dataLength);

    Auth::Response response = auth.getResponse(challenge);

    memcpy(echoSendPayloadBuffer(), (char *)&response, sizeof(Auth::Response));
    sendEchoToServer(TunnelHeader::TYPE_CHALLENGE_RESPONSE, sizeof(Auth::Response));

    setTimeout(5000);
}

bool Client::handleEchoData(const TunnelHeader &header, int dataLength,
                            const Echo::Address &realAddress, bool reply, uint16_t id,
                            uint16_t seq)
{
    if (!reply)
        return false;

    TunnelHeader::Type messageType = (TunnelHeader::Type)header.type;
    if (protocolVersion == 5)
    {
        const int rawLength = dataLength + (int)sizeof(TunnelHeader);
        if (state == STATE_CONNECTION_REQUEST_SENT)
        {
            std::vector<uint8_t> plain;
            if (!HandshakeEnvelopeV5::open(
                    handshakeKeyV5,
                    (const uint8_t *)rawEchoReceivePayloadBuffer(),
                    rawLength, plain))
                return true;
            // The kernel may echo the authenticated initiation before the
            // userspace server response. It is valid but not a response.
            if (plain.size() != 105 || plain[0] != V5_HANDSHAKE_RESPONSE ||
                get32((const char *)&plain[5]) != localReceiverIndex)
                return true;
            peerReceiverIndex = get32((const char *)&plain[1]);
            if (peerReceiverIndex == 0 || secureHandshake == NULL ||
                !secureHandshake->readMessage2(&plain[9], 96))
                throw Exception("invalid secure v5 handshake response");
            const string serverFingerprint = SecureIdentity::fingerprint(
                secureHandshake->remoteStaticKey());
            if (!expectedServerFingerprint.empty() &&
                serverFingerprint != expectedServerFingerprint)
                throw Exception("secure server fingerprint mismatch");
            if (realAddress != serverAddress)
            {
                syslog(LOG_INFO,
                       "authenticated server handshake moved from %s to %s",
                       serverAddress.format().c_str(),
                       realAddress.format().c_str());
                serverAddress = realAddress;
            }
            syslog(LOG_INFO, "secure server fingerprint %s",
                   serverFingerprint.c_str());
            protocolRequestAttempts = 0;
            sendV5HandshakeFinish();
            return true;
        }

        if (realAddress != serverAddress || !secureTransport.ready())
            return false;
        if (!openV5Packet(messageType, dataLength))
            return true;
    }

    // A raw IPv6 socket is not tied to the destination address that received
    // a request.  On a multi-address server the kernel may therefore choose a
    // different local source for the Noise response.  Admit only the v4
    // handshake response here; its PSK, server static key and optional pin are
    // authenticated below before the new address is trusted.  Legacy
    // handshakes and all established traffic retain strict address matching.
    bool authenticatableHandshakeSource =
        protocolVersion == 4 && state == STATE_CONNECTION_REQUEST_SENT &&
        header.magic == Server::v4Magic &&
        header.type == TunnelHeader::TYPE_HANDSHAKE_RESPONSE;
    if (realAddress != serverAddress && !authenticatableHandshakeSource)
        return false;

    if (protocolVersion != 5 && header.magic != serverMagic())
        return false;

    if (protocolVersion == 4 && state == STATE_CONNECTION_REQUEST_SENT &&
        header.type == TunnelHeader::TYPE_HANDSHAKE_RESPONSE)
    {
        if (dataLength != 104 || get32(echoReceivePayloadBuffer() + 4) !=
                                 localReceiverIndex)
            return true;
        peerReceiverIndex = get32(echoReceivePayloadBuffer());
        if (peerReceiverIndex == 0 || secureHandshake == NULL ||
            !secureHandshake->readMessage2(
                (const uint8_t *)echoReceivePayloadBuffer() + 8, 96))
            throw Exception("invalid secure handshake response");
        const string serverFingerprint = SecureIdentity::fingerprint(
            secureHandshake->remoteStaticKey());
        if (!expectedServerFingerprint.empty() &&
            serverFingerprint != expectedServerFingerprint)
            throw Exception("secure server fingerprint mismatch");
        if (realAddress != serverAddress)
        {
            syslog(LOG_INFO,
                   "authenticated server handshake moved from %s to %s",
                   serverAddress.format().c_str(),
                   realAddress.format().c_str());
            serverAddress = realAddress;
        }
        syslog(LOG_INFO, "secure server fingerprint %s",
               serverFingerprint.c_str());
        protocolRequestAttempts = 0;
        sendV4HandshakeFinish();
        return true;
    }

    if (protocolVersion == 4 && secureTransport.ready() &&
        header.type != TunnelHeader::TYPE_HANDSHAKE_RESPONSE)
    {
        if (!openV4Packet(header, dataLength))
            return true;
    }

    TransportV3::Header transport;
    TransportReorderBuffer::Action reorderAction =
        TransportReorderBuffer::IGNORE_CURRENT;
    vector<vector<char> > reorderedPackets;
    if (state == STATE_ESTABLISHED && protocolVersion >= 3)
    {
        if (!parseTransportHeader(dataLength, transport, id, seq))
            return true;
        bool isData = messageType == TunnelHeader::TYPE_DATA;
        reorderAction = reorderBuffer.observe(
            transport.txSequence, isData,
            echoReceivePayloadBuffer() + TransportV3::HEADER_SIZE,
            dataLength, now.milliseconds(), reorderedPackets);
        if (receivedSequences.lateCount() != 0)
            reorderBuffer.enable();
        if (!isData)
            deliverReorderedPackets(reorderedPackets);
        logTransportTelemetry();
    }

    switch (messageType)
    {
        case TunnelHeader::TYPE_RESET_CONNECTION:
            syslog(LOG_DEBUG, "reset received");

            if (state == STATE_ESTABLISHED)
            {
                if (protocolVersion < 4)
                    protocolVersion = 4;
                protocolRequestAttempts = 0;
            }
            // A server also uses RESET to retire an old session from this
            // real IP during a normal reconnect. Retry the same negotiation;
            // sendConnectionRequest() performs bounded timeout-based v3 ->
            // v2 -> v1 fallback if that protocol truly is unsupported.
            sendConnectionRequest();
            return true;
        case TunnelHeader::TYPE_SERVER_FULL:
            if (state == STATE_CONNECTION_REQUEST_SENT)
            {
                throw Exception("server full");
            }
            break;
        case TunnelHeader::TYPE_CHALLENGE:
            if (state == STATE_CONNECTION_REQUEST_SENT)
            {
                syslog(LOG_DEBUG, "authentication request received");
                protocolRequestAttempts = 0;
                sendChallengeResponse(dataLength);
                return true;
            }
            break;
        case TunnelHeader::TYPE_CONNECTION_ACCEPT:
            if (state == STATE_CHALLENGE_RESPONSE_SENT)
            {
                int expectedLength = protocolVersion >= 3 ? 12 :
                                     (int)sizeof(uint32_t);
                if (dataLength != expectedLength)
                {
                    throw Exception("invalid ip received");
                    return true;
                }

                syslog(LOG_INFO, "connection established");

                uint32_t ip;
                memcpy(&ip, echoReceivePayloadBuffer(), sizeof(ip));
                ip = ntohl(ip);
                if (protocolVersion >= 3)
                {
                    sessionId = get32(echoReceivePayloadBuffer() + 4);
                    negotiatedCapabilities =
                        (uint8_t)echoReceivePayloadBuffer()[8];
                    transportMode = (uint8_t)echoReceivePayloadBuffer()[9];
                    peerTransportMode = transportMode;
                    if (sessionId == 0 ||
                        (transportMode != TransportV3::MODE_CREDIT &&
                         transportMode != TransportV3::MODE_DIRECT))
                        throw Exception("invalid transport negotiation received");
                    if (protocolVersion >= 4)
                    {
                        uint16_t negotiatedMtu;
                        memcpy(&negotiatedMtu,
                               echoReceivePayloadBuffer() + 10,
                               sizeof(negotiatedMtu));
                        negotiatedMtu = ntohs(negotiatedMtu);
                        if (negotiatedMtu >= 68 && negotiatedMtu <= tunnelMtu)
                        {
                            if (negotiatedMtu < tunnelMtu)
                            {
                                tunnelMtu = negotiatedMtu;
                                tun.setMtu(tunnelMtu);
                                if (userspaceNetwork != NULL)
                                    userspaceNetwork->setMtu(tunnelMtu);
                            }
                            syslog(LOG_INFO, "negotiated tunnel MTU %d",
                                   tunnelMtu);
                        }
                    }
                }
                if (ip != clientIp)
                {
                    if (privilegesDropped)
                        throw Exception("could not get the same ip address, so root privileges are required to change it");

                    clientIp = ip;
                    desiredIp = ip;
                    if (userspaceNetwork != NULL)
                        userspaceNetwork->configure(ip, (ip & 0xffffff00) + 1);
                    else
                        tun.setIp(ip, (ip & 0xffffff00) + 1);
                }
                state = STATE_ESTABLISHED;
                lastServerPacket = now;
                lastTransportPing = Time::ZERO;
                v4ReconnectDeadline = Time::ZERO;

                dropPrivileges();
                startPolling();

                return true;
            }
            break;
        case TunnelHeader::TYPE_CHALLENGE_ERROR:
            if (state == STATE_CHALLENGE_RESPONSE_SENT)
            {
                throw Exception("password error");
            }
            break;
        case TunnelHeader::TYPE_IDENTITY_IN_USE:
            if (state == STATE_CHALLENGE_RESPONSE_SENT &&
                protocolVersion >= 4)
            {
                unsigned int retry = 3000 + Utility::random32() % 2001;
                syslog(LOG_WARNING,
                       "device identity is already active; retrying in %u ms",
                       retry);
                protocolRequestAttempts = 0;
                secureTransport.reset();
                setTimeout(Time((int)retry));
                return true;
            }
            break;
        case TunnelHeader::TYPE_DATA:
            if (state == STATE_ESTABLISHED)
            {
                if (protocolVersion >= 3)
                {
                    if (reorderAction == TransportReorderBuffer::DELIVER_CURRENT)
                        handleDataFromServer(dataLength);
                    deliverReorderedPackets(reorderedPackets);
                }
                else
                    handleDataFromServer(dataLength);
                return true;
            }
            break;
        case TunnelHeader::TYPE_DIRECT_PROBE_REPLY:
            if (state == STATE_ESTABLISHED && protocolVersion >= 3)
            {
                if (directProbePending)
                {
                    directProbeReplies++;
                    if (directProbeReplies >= 2)
                    {
                        directProbePending = false;
                        syslog(LOG_INFO, "direct reply probe succeeded; requesting direct mode");
                        requestMode(TransportV3::MODE_DIRECT);
                    }
                }
                // The third redundant probe reply can arrive after the second
                // one has already completed negotiation; it is still valid.
                return true;
            }
            break;
        case TunnelHeader::TYPE_MODE_ACK:
            if (state == STATE_ESTABLISHED && protocolVersion >= 3 &&
                dataLength == 1)
            {
                uint8_t acceptedMode =
                    (uint8_t)echoReceivePayloadBuffer()[TransportV3::HEADER_SIZE];
                if (acceptedMode == TransportV3::MODE_DIRECT)
                {
                    transportMode = acceptedMode;
                    outstandingPolls.clear();
                    syslog(LOG_INFO, "direct reply mode enabled");
                }
                else if (acceptedMode == TransportV3::MODE_CREDIT)
                {
                    switchToCredit("server requested credit fallback");
                    fillPollWindow();
                }
                return true;
            }
            break;
        case TunnelHeader::TYPE_TRANSPORT_PING:
            if (state == STATE_ESTABLISHED && protocolVersion >= 3)
                return true;
            break;
        default:
            break;
    }

    syslog(LOG_DEBUG, "invalid packet type: %d, state: %d", messageType, state);

    return true;
}

void Client::sendEchoToServer(Worker::TunnelHeader::Type type, int dataLength)
{
    if (!autoPoll && maxPolls == 0 && state == STATE_ESTABLISHED &&
        protocolVersion < 4)
        setTimeout(KEEP_ALIVE_INTERVAL);

    sendEcho(clientMagic(), type, dataLength,
             serverAddress, false, nextEchoId, nextEchoSequence);

    if (changeEchoId)
        nextEchoId = nextEchoId + 38543; // some random prime
    if (changeEchoSeq)
        nextEchoSequence = nextEchoSequence + 38543; // some random prime
}

const Worker::TunnelHeader::Magic &Client::clientMagic() const
{
    if (protocolVersion == 4)
        return v4Magic;
    if (protocolVersion == 3)
        return v3Magic;
    if (protocolVersion == 2)
        return v2Magic;
    return magic;
}

const Worker::TunnelHeader::Magic &Client::serverMagic() const
{
    if (protocolVersion == 4)
        return Server::v4Magic;
    if (protocolVersion == 3)
        return Server::v3Magic;
    if (protocolVersion == 2)
        return Server::v2Magic;
    return Server::magic;
}

uint32_t Client::echoKey(uint16_t id, uint16_t seq) const
{
    return ((uint32_t)id << 16) | seq;
}

void Client::sendV3ToServer(Worker::TunnelHeader::Type type, int dataLength,
                            uint8_t flags, bool trackPoll)
{
    char *payload = echoSendPayloadBuffer();
    char *transportPayload = payload;
    uint8_t *v5Packet = NULL;
    if (protocolVersion == 5)
    {
        v5Packet = (uint8_t *)rawEchoSendPayloadBuffer();
        if (dataLength > 0)
            memmove(v5Packet + SecureTransport::PREFIX_SIZE + 1 +
                              TransportV3::HEADER_SIZE,
                    payload, dataLength);
        v5Packet[SecureTransport::PREFIX_SIZE] = (uint8_t)type;
        transportPayload = (char *)v5Packet + SecureTransport::PREFIX_SIZE + 1;
    }
    else if (protocolVersion == 4)
    {
        if (dataLength > 0)
            memmove(payload + SecureTransport::PREFIX_SIZE +
                            TransportV3::HEADER_SIZE,
                    payload, dataLength);
        transportPayload += SecureTransport::PREFIX_SIZE;
    }
    else if (dataLength > 0)
        memmove(payload + TransportV3::HEADER_SIZE, payload, dataLength);

    TransportV3::Header transport;
    transport.flags = flags;
    transport.mode = transportMode;
    transport.creditTarget = (uint8_t)adaptiveCredit.target();
    transport.sessionId = sessionId;
    transport.txSequence = ++nextTransportSequence;
    if (transport.txSequence == 0)
        transport.txSequence = ++nextTransportSequence;
    transport.ackSequence = receivedSequences.ackSequence();
    transport.ackBits = receivedSequences.ackBits();
    transport.timestamp = (uint16_t)((now.milliseconds() / 16) & 0xffff);
    TransportV3::encode(transportPayload, transport);

    uint16_t sentId = nextEchoId;
    uint16_t sentSeq = nextEchoSequence;
    int wireLength = dataLength + TransportV3::HEADER_SIZE;
    if (protocolVersion == 5)
    {
        int plainLength = wireLength + 1;
        if (!secureTransport.sealPrepared(
                V5_CLIENT_DATA_AD, sizeof(V5_CLIENT_DATA_AD) - 1,
                v5Packet, plainLength, rawPayloadBufferSize()))
            throw Exception("encrypting tunnel packet");
        wireLength = plainLength + SecureTransport::OVERHEAD;
        sendRawEcho(wireLength, serverAddress, false,
                    nextEchoId, nextEchoSequence);
        if (changeEchoId)
            nextEchoId = nextEchoId + 38543;
        if (changeEchoSeq)
            nextEchoSequence = nextEchoSequence + 38543;
    }
    else if (protocolVersion == 4)
    {
        TunnelHeader ad;
        ad.magic = clientMagic();
        ad.type = type;
        if (!secureTransport.sealPrepared(
                (const uint8_t *)&ad, sizeof(ad), (uint8_t *)payload,
                wireLength, payloadBufferSize()))
            throw Exception("encrypting tunnel packet");
        wireLength += SecureTransport::OVERHEAD;
        sendEchoToServer(type, wireLength);
    }
    else
        sendEchoToServer(type, wireLength);
    // Adaptive credits need a unique request token so replies can be matched
    // to their send time even when the legacy -q option was not requested.
    if (!changeEchoSeq)
#if HANS_SEQUENTIAL_ECHO_SEQUENCE
        TransportV3::advanceEchoToken(nextEchoId, nextEchoSequence);
#else
        nextEchoSequence = nextEchoSequence + 38543;
#endif
    if (trackPoll)
        outstandingPolls[echoKey(sentId, sentSeq)] = now;
}

bool Client::openV4Packet(const TunnelHeader &header, int &dataLength)
{
    // Multiple local processes (and multiple peers behind one NAT) can see
    // the same raw ICMP replies. Receiver indexes provide cheap demux before
    // AEAD; only a packet addressed to this session merits an auth warning.
    if (dataLength < 4 || get32(echoReceivePayloadBuffer()) !=
                          localReceiverIndex)
        return false;
    size_t plainLength = 0;
    SecureTransport::OpenStatus openStatus;
    if (!secureTransport.openInPlace(
            (const uint8_t *)&header, sizeof(header),
            (uint8_t *)echoReceivePayloadBuffer(), dataLength, plainLength,
            &openStatus))
    {
        if (openStatus == SecureTransport::OPEN_AUTH_FAILED)
            logUnauthenticatedPacket(4);
        return false;
    }
    dataLength = (int)plainLength;
    return true;
}

bool Client::openV5Packet(TunnelHeader::Type &type, int &dataLength)
{
    uint8_t *packet = (uint8_t *)rawEchoReceivePayloadBuffer();
    size_t packetLength = (size_t)dataLength + sizeof(TunnelHeader);
    if (packetLength < SecureTransport::OVERHEAD + 1 ||
        get32((const char *)packet) != localReceiverIndex)
        return false;
    size_t plainLength = 0;
    SecureTransport::OpenStatus openStatus;
    if (!secureTransport.openInPlace(
            V5_SERVER_DATA_AD, sizeof(V5_SERVER_DATA_AD) - 1,
            packet, packetLength, plainLength, &openStatus))
    {
        if (openStatus == SecureTransport::OPEN_AUTH_FAILED)
            logUnauthenticatedPacket(5);
        return false;
    }
    if (plainLength < 1)
        return false;
    uint8_t rawType = packet[0];
    if (rawType < TunnelHeader::TYPE_RESET_CONNECTION ||
        rawType > TunnelHeader::TYPE_IDENTITY_IN_USE)
        return false;
    type = (TunnelHeader::Type)rawType;
    dataLength = (int)plainLength - 1;
    if (dataLength > 0)
        memmove(echoReceivePayloadBuffer(), packet + 1, dataLength);
    return true;
}

void Client::logUnauthenticatedPacket(int version)
{
    const int AUTH_WARNING_INTERVAL_MS = 5000;
    if (lastUnauthenticatedWarning != Time::ZERO &&
        !(lastUnauthenticatedWarning + Time(AUTH_WARNING_INTERVAL_MS) < now))
        return;
    lastUnauthenticatedWarning = now;
    syslog(LOG_WARNING, "discarding unauthenticated protocol v%d packet",
           version);
}

bool Client::parseTransportHeader(int &dataLength,
                                  TransportV3::Header &transport,
                                  uint16_t id, uint16_t seq)
{
    if (!TransportV3::decode(echoReceivePayloadBuffer(), dataLength, transport) ||
        transport.sessionId != sessionId)
    {
        syslog(LOG_WARNING, "discarding invalid transport v3 packet");
        return false;
    }

    if (!receivedSequences.accept(transport.txSequence))
        return false;

    lastServerPacket = now;
    v4ReconnectDeadline = Time::ZERO;
    peerTransportMode = transport.mode;
    dataLength -= TransportV3::HEADER_SIZE;

    std::map<uint32_t, Time>::iterator poll =
        outstandingPolls.find(echoKey(id, seq));
    if (poll != outstandingPolls.end())
    {
        int oldTarget = adaptiveCredit.target();
        int rtt = (now - poll->second).milliseconds();
        outstandingPolls.erase(poll);
        adaptiveCredit.onReply(transport.queuedPackets, rtt);
        if (adaptiveCredit.target() != oldTarget)
            syslog(LOG_INFO, "adaptive poll target changed %d -> %d (rtt=%dms, queued=%u)",
                   oldTarget, adaptiveCredit.target(), adaptiveCredit.rttMs(),
                   (unsigned int)transport.queuedPackets);
    }

    if (transport.mode == TransportV3::MODE_CREDIT &&
        transportMode == TransportV3::MODE_DIRECT)
        switchToCredit("server transport header announced credit mode");

    if (transportMode == TransportV3::MODE_CREDIT)
        fillPollWindow();
    return true;
}

void Client::startPolling()
{
    if (protocolVersion >= 3)
    {
        if (autoPoll &&
            (negotiatedCapabilities & TransportV3::CAP_ADAPTIVE_CREDIT))
        {
            transportMode = TransportV3::MODE_CREDIT;
            adaptiveCredit.reset();
            fillPollWindow();
            setTimeout(TRANSPORT_TICK_MS);
        }
        else if (maxPolls == 0)
        {
            transportMode = TransportV3::MODE_DIRECT;
            setTimeout(protocolVersion >= 4 ? DIRECT_HEARTBEAT_MS :
                       KEEP_ALIVE_INTERVAL);
        }
        else
        {
            for (int i = 0; i < maxPolls; ++i)
                sendV3ToServer(TunnelHeader::TYPE_POLL, 0,
                               TransportV3::FLAG_NONE, false);
            setTimeout(POLL_INTERVAL);
        }
    }
    else if (maxPolls == 0)
    {
        setTimeout(KEEP_ALIVE_INTERVAL);
    }
    else
    {
        for (int i = 0; i < maxPolls; i++)
            sendEchoToServer(TunnelHeader::TYPE_POLL, 0);
        setTimeout(POLL_INTERVAL);
    }
}

void Client::fillPollWindow()
{
    if (state != STATE_ESTABLISHED || protocolVersion < 3 ||
        transportMode != TransportV3::MODE_CREDIT)
        return;

    while ((int)outstandingPolls.size() < adaptiveCredit.target())
        sendV3ToServer(TunnelHeader::TYPE_POLL, 0,
                       TransportV3::FLAG_NONE, true);
}

void Client::startDirectProbe()
{
    if ((negotiatedCapabilities & TransportV3::CAP_DIRECT_REPLY) == 0 ||
        directProbePending || transportMode != TransportV3::MODE_CREDIT)
        return;

    directProbePending = true;
    directProbeReplies = 0;
    directProbeDeadline = now + Time(DIRECT_PROBE_TIMEOUT_MS);
    lastDirectProbe = now;
    syslog(LOG_INFO, "probing whether multiple direct echo replies pass the path");
    sendV3ToServer(TunnelHeader::TYPE_DIRECT_PROBE, 0,
                   TransportV3::FLAG_CONTROL, false);
}

void Client::requestMode(uint8_t mode)
{
    echoSendPayloadBuffer()[0] = mode;
    sendV3ToServer(TunnelHeader::TYPE_MODE_SET, 1,
                   TransportV3::FLAG_CONTROL, false);
    lastModeRequest = now;
}

void Client::switchToCredit(const char *reason)
{
    if (transportMode != TransportV3::MODE_CREDIT)
        syslog(LOG_WARNING, "falling back to adaptive poll credits: %s", reason);
    transportMode = TransportV3::MODE_CREDIT;
    directProbePending = false;
    adaptiveCredit.reset();
    // Give the failed path a quiet period before probing it again.
    lastDirectProbe = now;
    outstandingPolls.clear();
}

bool Client::maintainV4Session()
{
    if (protocolVersion < 4 || state != STATE_ESTABLISHED)
        return false;

    const int heartbeatInterval = transportMode == TransportV3::MODE_DIRECT ?
        DIRECT_HEARTBEAT_MS : V4_CREDIT_HEARTBEAT_MS;
    if (lastTransportPing == Time::ZERO ||
        now > lastTransportPing + Time(heartbeatInterval))
    {
        sendV3ToServer(TunnelHeader::TYPE_TRANSPORT_PING, 0,
                       TransportV3::FLAG_CONTROL, false);
        lastTransportPing = now;
    }

    if (!(now > lastServerPacket + Time(V4_SESSION_TIMEOUT_MS)))
    {
        v4ReconnectDeadline = Time::ZERO;
        return false;
    }

    if (v4ReconnectDeadline == Time::ZERO)
    {
        unsigned int jitter = Utility::random32() %
                              (V4_RECONNECT_JITTER_MS + 1);
        v4ReconnectDeadline = now + Time((int)jitter);
        syslog(LOG_WARNING,
               "authenticated protocol v%d heartbeat timed out; reconnecting in %u ms",
               protocolVersion, jitter);
        return false;
    }
    if (v4ReconnectDeadline > now)
        return false;

    restartV4Session();
    return true;
}

void Client::restartV4Session()
{
    syslog(LOG_WARNING, "reconnecting expired secure protocol v%d session",
           protocolVersion);
    if (protocolVersion < 4)
        protocolVersion = 4;
    protocolRequestAttempts = 0;
    negotiatedCapabilities = 0;
    sessionId = 0;
    transportMode = TransportV3::MODE_CREDIT;
    peerTransportMode = TransportV3::MODE_CREDIT;
    directProbePending = false;
    directProbeReplies = 0;
    outstandingPolls.clear();
    receivedSequences = SequenceTracker();
    reorderBuffer = TransportReorderBuffer();
    adaptiveCredit.reset();
    secureTransport.reset();
    nextTransportSequence = Utility::random32();
    lastDirectProbe = Time::ZERO;
    directProbeDeadline = Time::ZERO;
    lastServerPacket = Time::ZERO;
    lastTransportPing = Time::ZERO;
    lastModeRequest = Time::ZERO;
    lastTransportTelemetry = Time::ZERO;
    v4ReconnectDeadline = Time::ZERO;
    state = STATE_CLOSED;
    sendConnectionRequest();
}

void Client::transportTick()
{
    if (maintainV4Session())
        return;

    if (transportMode == TransportV3::MODE_CREDIT)
    {
        // A poll credit intentionally receives no reply while the server has
        // no data. Refresh old tokens so a request lost in the network cannot
        // permanently consume the local window, but do not interpret silence
        // as congestion or shrink the target.
        Time expiry = Time(CREDIT_REFRESH_MS);
        std::map<uint32_t, Time>::iterator it = outstandingPolls.begin();
        while (it != outstandingPolls.end())
        {
            std::map<uint32_t, Time>::iterator current = it++;
            if (now > current->second + expiry)
                outstandingPolls.erase(current);
        }
        fillPollWindow();

        if (peerTransportMode != TransportV3::MODE_CREDIT &&
            (lastModeRequest == Time::ZERO ||
             now > lastModeRequest + Time(DIRECT_HEARTBEAT_MS)))
            requestMode(TransportV3::MODE_CREDIT);

        if (directProbePending && now > directProbeDeadline)
        {
            syslog(LOG_INFO, "direct reply probe failed; keeping adaptive poll credits");
            directProbePending = false;
        }
        if (!directProbePending &&
            (lastDirectProbe == Time::ZERO ||
             now > lastDirectProbe + Time(DIRECT_REPROBE_INTERVAL_MS)))
            startDirectProbe();
    }
    else
    {
        if (protocolVersion < 4 &&
            (lastTransportPing == Time::ZERO ||
             now > lastTransportPing + Time(DIRECT_HEARTBEAT_MS)))
        {
            sendV3ToServer(TunnelHeader::TYPE_TRANSPORT_PING, 0,
                           TransportV3::FLAG_CONTROL, false);
            lastTransportPing = now;
        }

        if (now > lastServerPacket + Time(DIRECT_WATCHDOG_MS))
        {
            switchToCredit("direct heartbeat timed out");
            requestMode(TransportV3::MODE_CREDIT);
            // Send new credits only after the mode-change request. The server
            // intentionally ignores credits while it still believes direct
            // mode is active.
            fillPollWindow();
        }
    }

    setTimeout(TRANSPORT_TICK_MS);
}

void Client::handleDataFromServer(int dataLength)
{
    if (dataLength == 0)
    {
        syslog(LOG_WARNING, "received empty data packet");
        return;
    }

    const char *packet = protocolVersion >= 3 ?
        echoReceivePayloadBuffer() + TransportV3::HEADER_SIZE :
        echoReceivePayloadBuffer();
    handleDataPacket(packet, dataLength);
}

void Client::handleDataPacket(const char *packet, int dataLength)
{
    if (userspaceNetwork != NULL)
        userspaceNetwork->ingest(packet, dataLength);
    else if (protocolVersion >= 3)
        tun.write(packet, dataLength);
    else
        sendToTun(dataLength);

    if (protocolVersion >= 3)
    {
        if (autoPoll)
            fillPollWindow();
        else if (maxPolls != 0)
            sendV3ToServer(TunnelHeader::TYPE_POLL, 0,
                           TransportV3::FLAG_NONE, false);
    }
    else if (maxPolls != 0)
        sendEchoToServer(TunnelHeader::TYPE_POLL, 0);
}

void Client::deliverReorderedPackets(vector<vector<char> > &packets)
{
    for (size_t i = 0; i < packets.size(); ++i)
        if (!packets[i].empty())
            handleDataPacket(&packets[i][0], (int)packets[i].size());
    packets.clear();
}

void Client::logTransportTelemetry()
{
    bool anomalies = receivedSequences.gapCount() != 0 ||
                     receivedSequences.duplicateCount() != 0 ||
                     reorderBuffer.releasedGapCount() != 0;
    if (!anomalies ||
        (lastTransportTelemetry != Time::ZERO &&
         !(lastTransportTelemetry + Time(5000) < now)))
        return;
    lastTransportTelemetry = now;
    syslog(LOG_DEBUG,
           "transport rx=%" PRIu64 " gaps=%" PRIu64 " missing=%" PRIu64
           " late=%" PRIu64 " dup=%" PRIu64 " held=%" PRIu64
           " released=%" PRIu64 " skipped=%" PRIu64
           " late-release=%" PRIu64 " depth=%u",
           receivedSequences.acceptedCount(),
           receivedSequences.gapCount(),
           receivedSequences.missingCount(),
           receivedSequences.lateCount(),
           receivedSequences.duplicateCount(),
           reorderBuffer.bufferedCount(),
           reorderBuffer.releasedGapCount(),
           reorderBuffer.skippedCount(),
           reorderBuffer.lateReleaseCount(),
           (unsigned int)reorderBuffer.maximumDepth());
}

void Client::handleTunData(int dataLength, uint32_t, uint32_t)
{
    if (state != STATE_ESTABLISHED)
        return;

    if (protocolVersion >= 3)
        sendV3ToServer(TunnelHeader::TYPE_DATA, dataLength,
                       TransportV3::FLAG_NONE, false);
    else
        sendEchoToServer(TunnelHeader::TYPE_DATA, dataLength);
}

void Client::handleTimeout()
{
    switch (state)
    {
        case STATE_CONNECTION_REQUEST_SENT:
        case STATE_CHALLENGE_RESPONSE_SENT:
            sendConnectionRequest();
            break;

        case STATE_ESTABLISHED:
            if (protocolVersion >= 4 && !autoPoll)
            {
                if (maintainV4Session())
                    break;
                if (maxPolls == 0)
                {
                    setTimeout(DIRECT_HEARTBEAT_MS);
                    break;
                }
            }
            if (protocolVersion >= 3)
            {
                if (autoPoll)
                    transportTick();
                else
                {
                    sendV3ToServer(maxPolls == 0 ?
                                   TunnelHeader::TYPE_TRANSPORT_PING :
                                   TunnelHeader::TYPE_POLL, 0,
                                   TransportV3::FLAG_CONTROL, false);
                    setTimeout(maxPolls == 0 ? KEEP_ALIVE_INTERVAL :
                               POLL_INTERVAL);
                }
            }
            else
            {
                sendEchoToServer(TunnelHeader::TYPE_POLL, 0);
                setTimeout(maxPolls == 0 ? KEEP_ALIVE_INTERVAL : POLL_INTERVAL);
            }
            break;
        case STATE_CLOSED:
            break;
    }
}

void Client::run()
{
    now = Time::now();

    sendConnectionRequest();

    Worker::run();
}

int Client::addFileDescriptors(fd_set &readSet, fd_set &writeSet, int maxFd)
{
    if (userspaceNetwork == NULL)
        return maxFd;
    return userspaceNetwork->addFileDescriptors(readSet, writeSet, maxFd);
}

void Client::handleFileDescriptors(fd_set &readSet, fd_set &writeSet)
{
    if (userspaceNetwork != NULL)
        userspaceNetwork->handleFileDescriptors(readSet, writeSet);
}

int Client::idleIntervalMilliseconds() const
{
    int interval = userspaceNetwork == NULL ? -1 : 50;
    int reorderWait = reorderBuffer.waitMilliseconds(now.milliseconds());
    if (reorderWait >= 0 && (interval < 0 || reorderWait < interval))
        interval = reorderWait;
    return interval;
}

void Client::handleIdle()
{
    vector<vector<char> > packets;
    if (reorderBuffer.flushExpired(now.milliseconds(), packets))
    {
        deliverReorderedPackets(packets);
        logTransportTelemetry();
    }
    if (userspaceNetwork != NULL)
        userspaceNetwork->tick();
}

void Client::sendUserspacePacket(const char *packet, int length)
{
    if (length <= 0 || length > tunnelMtu)
    {
        syslog(LOG_WARNING, "userspace packet dropped: invalid length %d", length);
        return;
    }
    memcpy(echoSendPayloadBuffer(), packet, length);
    handleTunData(length, 0, 0);
}
