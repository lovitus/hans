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

Client::Client(int tunnelMtu, const string *deviceName, uint32_t serverIp,
               int maxPolls, const string &passphrase, uid_t uid, gid_t gid,
               bool changeEchoId, bool changeEchoSeq, uint32_t desiredIp,
               const string &deviceId, bool userspace,
               const string &socksAddress,
               const vector<SharePort> &sharePorts,
               const string &identityFile, bool requireV4,
               const string &serverFingerprint, const string &socksUser,
               const string &socksPassword)
    : Worker(tunnelMtu, deviceName, false, uid, gid, !userspace, userspace),
      auth(passphrase)
{
    this->serverIp = serverIp;
    this->clientIp = INADDR_NONE;
    this->desiredIp = desiredIp;
    this->autoPoll = maxPolls < 0;
    this->maxPolls = autoPoll ? 4 : maxPolls;
    this->nextEchoId = Utility::rand();
    this->changeEchoId = changeEchoId;
    this->changeEchoSeq = changeEchoSeq;
    this->nextEchoSequence = Utility::rand();
    this->deviceId = deviceId;
    this->protocolVersion = 4;
    this->protocolRequestAttempts = 0;
    this->requireV4 = requireV4;
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
    this->nextTransportSequence = Utility::random32();
    this->transportMode = TransportV3::MODE_CREDIT;
    this->peerTransportMode = TransportV3::MODE_CREDIT;
    this->directProbePending = false;
    this->directProbeReplies = 0;
    this->userspaceNetwork = userspace ?
        new UserspaceNetwork(this, tunnelMtu, socksAddress, sharePorts,
                             socksUser, socksPassword) : NULL;
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
    delete userspaceNetwork;
}

void Client::sendConnectionRequest()
{
    if (protocolRequestAttempts >= 2 && protocolVersion > 1)
    {
        if (protocolVersion == 4 && requireV4)
            throw Exception("secure protocol v4 handshake timed out; refusing downgrade");
        protocolVersion--;
        protocolRequestAttempts = 0;
        syslog(LOG_WARNING, "server did not answer protocol v%d handshake; falling back to v%d",
               protocolVersion + 1, protocolVersion);
    }

    syslog(LOG_DEBUG, "sending protocol v%d connection request", protocolVersion);

    if (protocolVersion == 4)
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
        connectData->capabilities = autoPoll ? TransportV3::ALL_CAPABILITIES :
                                              TransportV3::CAP_SEQUENCE_ACK;
#ifdef WIN32
        if (userspaceNetwork != NULL)
            connectData->capabilities |= TransportV3::CAP_WINDOWS_ICMP_HELPER;
#endif
        connectData->minimumPolls = 2;
        connectData->maximumPolls = 128;
        sendEchoToServer(TunnelHeader::TYPE_CONNECTION_REQUEST,
                         sizeof(Server::ClientConnectDataV3));
    }

    protocolRequestAttempts++;

    state = STATE_CONNECTION_REQUEST_SENT;
    setTimeout(5000);
}

void Client::sendV4HandshakeFinish()
{
    Server::ClientConnectDataV3 connectData;
    memset(&connectData, 0, sizeof(connectData));
    connectData.v2.legacy.maxPolls = autoPoll ? adaptiveCredit.target() : maxPolls;
    connectData.v2.legacy.desiredIp = desiredIp;
    memcpy(connectData.v2.deviceId, deviceId.data(), DEVICE_ID_HEX_SIZE);
    connectData.capabilities = autoPoll ? TransportV3::ALL_CAPABILITIES :
                                         TransportV3::CAP_SEQUENCE_ACK;
#ifdef WIN32
    if (userspaceNetwork != NULL)
        connectData.capabilities |= TransportV3::CAP_WINDOWS_ICMP_HELPER;
#endif
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
                            uint32_t realIp, bool reply, uint16_t id,
                            uint16_t seq)
{
    if (realIp != serverIp || !reply)
        return false;

    if (header.magic != serverMagic())
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
    if (state == STATE_ESTABLISHED && protocolVersion >= 3)
    {
        if (!parseTransportHeader(dataLength, transport, id, seq))
            return true;
    }

    switch (header.type)
    {
        case TunnelHeader::TYPE_RESET_CONNECTION:
            syslog(LOG_DEBUG, "reset received");

            if (state == STATE_ESTABLISHED)
            {
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
                    if (protocolVersion == 4)
                    {
                        uint16_t negotiatedMtu;
                        memcpy(&negotiatedMtu,
                               echoReceivePayloadBuffer() + 10,
                               sizeof(negotiatedMtu));
                        negotiatedMtu = ntohs(negotiatedMtu);
                        if (negotiatedMtu >= 68 && negotiatedMtu < tunnelMtu)
                        {
                            tunnelMtu = negotiatedMtu;
                            tun.setMtu(tunnelMtu);
                            if (userspaceNetwork != NULL)
                                userspaceNetwork->setMtu(tunnelMtu);
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
        case TunnelHeader::TYPE_DATA:
            if (state == STATE_ESTABLISHED)
            {
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

    syslog(LOG_DEBUG, "invalid packet type: %d, state: %d", header.type, state);

    return true;
}

void Client::sendEchoToServer(Worker::TunnelHeader::Type type, int dataLength)
{
    if (!autoPoll && maxPolls == 0 && state == STATE_ESTABLISHED)
        setTimeout(KEEP_ALIVE_INTERVAL);

    sendEcho(clientMagic(), type, dataLength,
             serverIp, false, nextEchoId, nextEchoSequence);

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
    if (dataLength > 0)
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
    TransportV3::encode(payload, transport);

    uint16_t sentId = nextEchoId;
    uint16_t sentSeq = nextEchoSequence;
    int wireLength = dataLength + TransportV3::HEADER_SIZE;
    if (protocolVersion == 4)
    {
        TunnelHeader ad;
        ad.magic = clientMagic();
        ad.type = type;
        std::vector<uint8_t> packet;
        if (!secureTransport.seal((const uint8_t *)&ad, sizeof(ad),
                                  (const uint8_t *)payload, wireLength, packet))
            throw Exception("encrypting tunnel packet");
        memcpy(payload, &packet[0], packet.size());
        wireLength = packet.size();
    }
    sendEchoToServer(type, wireLength);
    // Adaptive credits need a unique request token so replies can be matched
    // to their send time even when the legacy -q option was not requested.
    if (!changeEchoSeq)
        nextEchoSequence = nextEchoSequence + 38543;
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
    std::vector<uint8_t> plain;
    if (!secureTransport.open((const uint8_t *)&header, sizeof(header),
                              (const uint8_t *)echoReceivePayloadBuffer(),
                              dataLength, plain))
    {
        syslog(LOG_WARNING, "discarding unauthenticated protocol v4 packet");
        return false;
    }
    if (!plain.empty())
        memcpy(echoReceivePayloadBuffer(), &plain[0], plain.size());
    dataLength = plain.size();
    return true;
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
            setTimeout(KEEP_ALIVE_INTERVAL);
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

void Client::transportTick()
{
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
        if (lastTransportPing == Time::ZERO ||
            now > lastTransportPing + Time(DIRECT_HEARTBEAT_MS))
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
    return userspaceNetwork == NULL ? -1 : 50;
}

void Client::handleIdle()
{
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
