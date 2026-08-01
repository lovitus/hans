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

#include "server.h"
#include "client.h"
#include "config.h"
#include "utility.h"
#include "exception.h"

#include <string.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

using std::string;
using std::cout;
using std::endl;

#define FIRST_ASSIGNED_IP_OFFSET 100

const Worker::TunnelHeader::Magic Server::magic("hans");
const Worker::TunnelHeader::Magic Server::v2Magic("hns2");
const Worker::TunnelHeader::Magic Server::v3Magic("hns3");
const Worker::TunnelHeader::Magic Server::v4Magic("hns4");

namespace
{
    const int DIRECT_UNACKED_LIMIT = 3;
    const int DIRECT_ACK_TIMEOUT_MS = 3000;
    const int MAX_PENDING_SECURE_HANDSHAKES = 256;
    const int MAX_PENDING_SECURE_HANDSHAKES_PER_ADDRESS = 8;

    void put32(char *buffer, uint32_t value)
    {
        value = htonl(value);
        memcpy(buffer, &value, sizeof(value));
    }

    uint32_t get32(const char *buffer)
    {
        uint32_t value;
        memcpy(&value, buffer, sizeof(value));
        return ntohl(value);
    }

    uint16_t get16(const char *buffer)
    {
        uint16_t value;
        memcpy(&value, buffer, sizeof(value));
        return ntohs(value);
    }

    void put16(char *buffer, uint16_t value)
    {
        value = htons(value);
        memcpy(buffer, &value, sizeof(value));
    }
}

Server::Server(int tunnelMtu, const string *deviceName, const string &passphrase,
               uint32_t network, bool answerEcho, uid_t uid, gid_t gid, int pollTimeout,
               const string &leaseFile, const string &identityFile)
    : Worker(tunnelMtu, deviceName, answerEcho, uid, gid), auth(passphrase),
      kernelEchoGuard6("/proc/sys/net/ipv6/icmp/echo_ignore_all")
{
    this->network = network & 0xffffff00;
    this->pollTimeout = pollTimeout;
    this->latestAssignedIpOffset = FIRST_ASSIGNED_IP_OFFSET - 1;
    this->leaseFile = leaseFile;
    this->leaseFd = -1;
    secureIdentity.loadOrCreate(identityFile.empty() ?
                                Utility::defaultStateFile("server.key") :
                                identityFile);
    NoiseHandshake::derivePsk(passphrase, securePsk);

    tun.setIp(this->network + 1, this->network + 2);

    Utility::ensureParentDirectory(leaseFile);
    leaseFd = open(leaseFile.c_str(), O_RDWR | O_CREAT, 0600);
    if (leaseFd == -1)
        throw Exception("could not open lease file", true);
    loadLeases();

    dropPrivileges();
}

Server::~Server()
{
    for (ClientList::iterator client = clientList.begin();
         client != clientList.end(); ++client)
        delete client->secureHandshake;
    for (LeaseMap::iterator it = leases.begin(); it != leases.end(); ++it)
        it->second.active = false;
    saveLeases();
    if (leaseFd != -1)
        close(leaseFd);
    memset(securePsk, 0, sizeof(securePsk));
}

void Server::handleUnknownClient(const TunnelHeader &header, int dataLength, uint32_t realIp, uint16_t echoId, uint16_t echoSeq)
{
    ClientData client;
    client.realIp = realIp;
    client.realAddress = Echo::Address::ipv4(realIp);
    client.maxPolls = 1;
    client.protocolVersion = header.magic == Client::v3Magic ? 3 :
                             (header.magic == Client::v2Magic ? 2 : 1);
    client.capabilities = 0;
    client.autoPoll = false;
    client.transportMode = TransportV3::MODE_CREDIT;
    client.sessionId = 0;
    client.localReceiverIndex = 0;
    client.peerReceiverIndex = 0;
    client.secureHandshake = NULL;
    client.nextTransportSequence = Utility::random32();
    client.haveLastEcho = false;
    client.backlogHint = 0;
    client.state = ClientData::STATE_NEW;

    pollReceived(&client, echoId, echoSeq, false);

    if (header.type != TunnelHeader::TYPE_CONNECTION_REQUEST ||
        (client.protocolVersion == 3 && dataLength != sizeof(ClientConnectDataV3)) ||
        (client.protocolVersion == 2 && dataLength != sizeof(ClientConnectDataV2)) ||
        (client.protocolVersion == 1 && dataLength != sizeof(ClientConnectData)) ||
        (dataLength != sizeof(ClientConnectData) &&
         dataLength != sizeof(ClientConnectDataV2) &&
         dataLength != sizeof(ClientConnectDataV3)))
    {
        syslog(LOG_DEBUG, "invalid request (type %d) from %s", header.type,
               Utility::formatIp(realIp).c_str());
        sendReset(&client);
        return;
    }

    ClientConnectData *connectData = (ClientConnectData *)echoReceivePayloadBuffer();
    if (client.protocolVersion >= 2)
    {
        ClientConnectDataV2 *connectDataV2 =
            client.protocolVersion == 3 ?
            &((ClientConnectDataV3 *)echoReceivePayloadBuffer())->v2 :
            (ClientConnectDataV2 *)echoReceivePayloadBuffer();
        string receivedId(connectDataV2->deviceId, DEVICE_ID_HEX_SIZE);
        if (!Utility::isDeviceId(receivedId))
        {
            syslog(LOG_WARNING, "invalid device id from %s",
                   Utility::formatIp(realIp).c_str());
            sendReset(&client);
            return;
        }
        client.deviceId = Utility::normalizeDeviceId(receivedId);
        connectData = &connectDataV2->legacy;
    }

    if (client.protocolVersion == 3)
    {
        ClientConnectDataV3 *connectDataV3 =
            (ClientConnectDataV3 *)echoReceivePayloadBuffer();
        if (connectDataV3->capabilities &
            TransportV3::CAP_WINDOWS_ICMP_HELPER)
            kernelEchoGuard.suppress();
        client.capabilities = connectDataV3->capabilities &
                              TransportV3::ALL_CAPABILITIES;
        client.autoPoll =
            (client.capabilities & TransportV3::CAP_ADAPTIVE_CREDIT) != 0;
    }

    client.maxPolls = connectData->maxPolls;
    if (client.autoPoll)
    {
        if (client.maxPolls < 2)
            client.maxPolls = 2;
        if (client.maxPolls > 128)
            client.maxPolls = 128;
    }
    if (client.protocolVersion == 3 && !client.autoPoll &&
        client.maxPolls == 0)
        client.transportMode = TransportV3::MODE_DIRECT;
    client.desiredIp = connectData->desiredIp;
    bool replacingDevice = !client.deviceId.empty() &&
                           getClientByDeviceId(client.deviceId, NULL) != NULL;
    client.tunnelIp = replacingDevice ? 0 :
                      reserveTunnelIp(client.desiredIp, client.deviceId);

    syslog(LOG_DEBUG, "new client %s with tunnel address %s\n",
           Utility::formatIp(client.realIp).data(),
           Utility::formatIp(client.tunnelIp).data());

    if (client.tunnelIp != 0 || replacingDevice)
    {
        client.challenge = auth.generateChallenge(CHALLENGE_SIZE);
        sendChallenge(&client);

        // add client to list
        clientList.push_front(client);
        clientRealIpMap[realIp] = clientList.begin();
        if (client.tunnelIp != 0)
            clientTunnelIpMap[client.tunnelIp] = clientList.begin();
    }
    else
    {
        syslog(LOG_WARNING, "server full");
        sendEchoToClient(&client, TunnelHeader::TYPE_SERVER_FULL, 0);
    }
}

void Server::sendChallenge(ClientData *client)
{
    syslog(LOG_DEBUG, "sending authentication request to %s\n",
           Utility::formatIp(client->realIp).data());

    memcpy(echoSendPayloadBuffer(), &client->challenge[0], client->challenge.size());
    sendEchoToClient(client, TunnelHeader::TYPE_CHALLENGE, client->challenge.size());

    client->state = ClientData::STATE_CHALLENGE_SENT;
}

void Server::removeClient(ClientData *client)
{
    syslog(LOG_DEBUG, "removing client %s with tunnel ip %s\n",
           Utility::formatIp(client->realIp).data(),
           Utility::formatIp(client->tunnelIp).data());

    releaseTunnelIp(client->tunnelIp, client->deviceId);

    ClientList::iterator it = clientList.end();
    for (ClientList::iterator candidate = clientList.begin();
         candidate != clientList.end(); ++candidate)
        if (&*candidate == client)
        {
            it = candidate;
            break;
        }
    if (it == clientList.end())
        return;

    if (client->protocolVersion < 4)
        clientRealIpMap.erase(client->realIp);
    else
        clientReceiverIndexMap.erase(client->localReceiverIndex);
    clientTunnelIpMap.erase(client->tunnelIp);
    delete client->secureHandshake;
    client->secureHandshake = NULL;
    clientList.erase(it);
}

void Server::handleV4HandshakeInit(const TunnelHeader &, int dataLength,
                                   const Echo::Address &realAddress,
                                   uint16_t echoId,
                                   uint16_t echoSeq)
{
    if (dataLength != 36 && dataLength != 37)
        return;
    uint32_t peerIndex = get32(echoReceivePayloadBuffer());
    if (peerIndex == 0)
        return;
    const int noiseOffset = dataLength == 37 ? 5 : 4;
    if (dataLength == 37 &&
        ((uint8_t)echoReceivePayloadBuffer()[4] &
         TransportV3::CAP_WINDOWS_ICMP_HELPER) != 0)
    {
        if (realAddress.family() == AF_INET6)
            kernelEchoGuard6.suppress();
        else
            kernelEchoGuard.suppress();
    }

    int pending = 0;
    int pendingForAddress = 0;
    for (ClientList::iterator it = clientList.begin(); it != clientList.end(); ++it)
    {
        if (it->protocolVersion == 4 &&
            it->state == ClientData::STATE_CHALLENGE_SENT)
        {
            ++pending;
            if (it->realAddress == realAddress)
                ++pendingForAddress;
        }
    }
    if (pending >= MAX_PENDING_SECURE_HANDSHAKES ||
        pendingForAddress >= MAX_PENDING_SECURE_HANDSHAKES_PER_ADDRESS)
    {
        syslog(LOG_WARNING, "secure handshake limit reached for %s",
               realAddress.format().c_str());
        return;
    }

    ClientData client;
    client.realAddress = realAddress;
    client.realIp = realAddress.isIpv4() ? realAddress.ipv4Value() : 0;
    client.tunnelIp = 0;
    client.desiredIp = 0;
    client.protocolVersion = 4;
    client.capabilities = 0;
    client.autoPoll = false;
    client.transportMode = TransportV3::MODE_CREDIT;
    client.sessionId = 0;
    client.localReceiverIndex = 0;
    do client.localReceiverIndex = Utility::random32();
    while (clientReceiverIndexMap.count(client.localReceiverIndex));
    client.peerReceiverIndex = peerIndex;
    client.secureHandshake = new NoiseHandshake(NoiseHandshake::RESPONDER,
                                                 secureIdentity.secretKey(),
                                                 securePsk);
    client.nextTransportSequence = Utility::random32();
    client.haveLastEcho = false;
    client.backlogHint = 0;
    client.maxPolls = 1;
    client.state = ClientData::STATE_CHALLENGE_SENT;
    if (!client.secureHandshake->readMessage1(
            (const uint8_t *)echoReceivePayloadBuffer() + noiseOffset, 32))
    {
        delete client.secureHandshake;
        return;
    }
    pollReceived(&client, echoId, echoSeq, false);
    std::vector<uint8_t> response;
    if (!client.secureHandshake->writeMessage2(response))
    {
        delete client.secureHandshake;
        return;
    }
    clientList.push_front(client);
    clientReceiverIndexMap[client.localReceiverIndex] = clientList.begin();
    put32(echoSendPayloadBuffer(), client.localReceiverIndex);
    put32(echoSendPayloadBuffer() + 4, client.peerReceiverIndex);
    memcpy(echoSendPayloadBuffer() + 8, &response[0], response.size());
    sendEcho(v4Magic, TunnelHeader::TYPE_HANDSHAKE_RESPONSE,
             8 + response.size(), realAddress, true, echoId, echoSeq);
}

void Server::handleV4HandshakeFinish(const TunnelHeader &, int dataLength,
                                     const Echo::Address &realAddress,
                                     uint16_t echoId,
                                     uint16_t echoSeq)
{
    if (dataLength < 72)
        return;
    uint32_t peerIndex = get32(echoReceivePayloadBuffer());
    uint32_t localIndex = get32(echoReceivePayloadBuffer() + 4);
    ClientData *client = getClientByReceiverIndex(localIndex);
    if (client == NULL || client->state != ClientData::STATE_CHALLENGE_SENT ||
        client->peerReceiverIndex != peerIndex ||
        client->realAddress != realAddress ||
        client->secureHandshake == NULL)
        return;
    std::vector<uint8_t> decoded;
    if (!client->secureHandshake->readMessage3(
            (const uint8_t *)echoReceivePayloadBuffer() + 8,
            dataLength - 8, decoded) ||
        (decoded.size() != sizeof(ClientConnectDataV3) &&
         decoded.size() != sizeof(ClientConnectDataV3) + 2))
    {
        syslog(LOG_WARNING, "secure authentication failed for %s",
               realAddress.format().c_str());
        removeClient(client);
        return;
    }
    ClientConnectDataV3 connectData;
    memcpy(&connectData, &decoded[0], sizeof(connectData));
    uint16_t clientMtu = decoded.size() > sizeof(connectData) ?
        get16((const char *)&decoded[sizeof(connectData)]) : (uint16_t)tunnelMtu;
    if (clientMtu >= 68 && clientMtu < tunnelMtu)
    {
        tunnelMtu = clientMtu;
        tun.setMtu(tunnelMtu);
        syslog(LOG_INFO, "lowered server tunnel MTU to %d for path compatibility",
               tunnelMtu);
    }
    string receivedId(connectData.v2.deviceId, DEVICE_ID_HEX_SIZE);
    if (!Utility::isDeviceId(receivedId))
    {
        removeClient(client);
        return;
    }
    // In v4 the authenticated static Noise key is the durable device
    // identity.  The encrypted legacy field remains on the wire only for
    // layout compatibility and is never trusted for lease ownership.
    client->deviceId = SecureIdentity::fingerprint(
        client->secureHandshake->remoteStaticKey());
    client->desiredIp = connectData.v2.legacy.desiredIp;
    client->capabilities = connectData.capabilities & TransportV3::ALL_CAPABILITIES;
    client->autoPoll = (client->capabilities & TransportV3::CAP_ADAPTIVE_CREDIT) != 0;
    client->maxPolls = connectData.v2.legacy.maxPolls;
    if (client->autoPoll)
    {
        if (client->maxPolls < 2) client->maxPolls = 2;
        if (client->maxPolls > 128) client->maxPolls = 128;
    }
    if (!client->autoPoll && client->maxPolls == 0)
        client->transportMode = TransportV3::MODE_DIRECT;
    if (connectData.capabilities & TransportV3::CAP_WINDOWS_ICMP_HELPER)
    {
        if (client->realAddress.family() == AF_INET6)
            kernelEchoGuard6.suppress();
        else
            kernelEchoGuard.suppress();
    }

    ClientData *oldClient = getClientByDeviceId(client->deviceId, client);
    if (oldClient != NULL)
        removeClient(oldClient);
    client->tunnelIp = reserveTunnelIp(client->desiredIp, client->deviceId);
    if (client->tunnelIp == 0)
    {
        removeClient(client);
        return;
    }
    clientTunnelIpMap[client->tunnelIp] =
        clientReceiverIndexMap[client->localReceiverIndex];
    client->sessionId = Utility::random32();
    client->secureTransport.initialize(client->peerReceiverIndex,
                                       client->localReceiverIndex,
                                       client->secureHandshake->sendKey(),
                                       client->secureHandshake->receiveKey());
    delete client->secureHandshake;
    client->secureHandshake = NULL;
    pollReceived(client, echoId, echoSeq, false);

    char accept[12];
    put32(accept, client->tunnelIp);
    put32(accept + 4, client->sessionId);
    accept[8] = (char)client->capabilities;
    accept[9] = (char)client->transportMode;
    put16(accept + 10, (uint16_t)tunnelMtu);
    sendV4RawToClient(client, TunnelHeader::TYPE_CONNECTION_ACCEPT,
                      accept, sizeof(accept), echoId, echoSeq);
    client->state = ClientData::STATE_ESTABLISHED;
    updateLease(client, true);
    syslog(LOG_INFO, "secure protocol v4 connection established to %s (device %s)",
           realAddress.format().c_str(), client->deviceId.c_str());
}

void Server::checkChallenge(ClientData *client, int length)
{
    Auth::Response rightResponse = auth.getResponse(client->challenge);

    if (length != sizeof(Auth::Response) || memcmp(&rightResponse, echoReceivePayloadBuffer(), length) != 0)
    {
        syslog(LOG_DEBUG, "wrong challenge response from %s\n",
               Utility::formatIp(client->realIp).data());

        sendEchoToClient(client, TunnelHeader::TYPE_CHALLENGE_ERROR, 0);

        removeClient(client);
        return;
    }

    if (client->tunnelIp == 0)
    {
        ClientData *oldClient = getClientByDeviceId(client->deviceId, client);
        if (oldClient != NULL)
            removeClient(oldClient);

        client->tunnelIp = reserveTunnelIp(client->desiredIp, client->deviceId);
        if (client->tunnelIp == 0)
        {
            syslog(LOG_WARNING, "server full");
            sendEchoToClient(client, TunnelHeader::TYPE_SERVER_FULL, 0);
            removeClient(client);
            return;
        }
        clientTunnelIpMap[client->tunnelIp] = clientRealIpMap[client->realIp];
    }

    char *accept = echoSendPayloadBuffer();
    put32(accept, client->tunnelIp);
    int acceptLength = sizeof(uint32_t);
    if (client->protocolVersion == 3)
    {
        client->sessionId = Utility::random32();
        put32(accept + 4, client->sessionId);
        accept[8] = (char)client->capabilities;
        accept[9] = (char)client->transportMode;
        accept[10] = 0;
        accept[11] = 0;
        acceptLength = 12;
    }

    sendEchoToClient(client, TunnelHeader::TYPE_CONNECTION_ACCEPT, acceptLength);

    client->state = ClientData::STATE_ESTABLISHED;
    updateLease(client, true);

    syslog(LOG_INFO, "connection established to %s",
           Utility::formatIp(client->realIp).data());
}

void Server::sendReset(ClientData *client)
{
    syslog(LOG_DEBUG, "sending reset to %s",
           Utility::formatIp(client->realIp).data());
    sendEchoToClient(client, TunnelHeader::TYPE_RESET_CONNECTION, 0);
}

bool Server::handleEchoData(const TunnelHeader &header, int dataLength,
                            const Echo::Address &realAddress, bool reply,
                            uint16_t id, uint16_t seq)
{
    if (reply)
        return false;

    if (header.magic == Client::v4Magic)
    {
        if (header.type == TunnelHeader::TYPE_HANDSHAKE_INIT)
        {
            handleV4HandshakeInit(header, dataLength, realAddress, id, seq);
            return true;
        }
        if (header.type == TunnelHeader::TYPE_HANDSHAKE_FINISH)
        {
            handleV4HandshakeFinish(header, dataLength, realAddress, id, seq);
            return true;
        }
        if (dataLength < 4)
            return true;
        ClientData *secureClient = getClientByReceiverIndex(
            get32(echoReceivePayloadBuffer()));
        if (secureClient == NULL || secureClient->state != ClientData::STATE_ESTABLISHED ||
            !openV4Packet(secureClient, header, dataLength, realAddress))
            return true;
        ClientData *client = secureClient;
        TransportV3::Header transport;
        if (!parseTransportHeader(client, dataLength, transport))
            return true;
        processTransportAck(client, transport);
        if (client->autoPoll)
        {
            int requested = transport.creditTarget;
            if (requested < 2) requested = 2;
            if (requested > 128) requested = 128;
            client->maxPolls = requested;
        }
        bool isControl = header.type == TunnelHeader::TYPE_DIRECT_PROBE ||
                         header.type == TunnelHeader::TYPE_MODE_SET ||
                         header.type == TunnelHeader::TYPE_TRANSPORT_PING;
        pollReceived(client, id, seq, !isControl);
        // Continue in the common type switch below with the authenticated client.
        switch (header.type)
        {
            case TunnelHeader::TYPE_DATA:
                if (dataLength > 0)
                    handleClientData(
                        client,
                        echoReceivePayloadBuffer() + TransportV3::HEADER_SIZE,
                        dataLength);
                return true;
            case TunnelHeader::TYPE_POLL:
                return true;
            case TunnelHeader::TYPE_DIRECT_PROBE:
                if (client->autoPoll &&
                    (client->capabilities & TransportV3::CAP_DIRECT_REPLY))
                    sendDirectProbeReplies(client, id, seq);
                return true;
            case TunnelHeader::TYPE_MODE_SET:
                if (dataLength == 1)
                {
                    uint8_t requested = (uint8_t)echoReceivePayloadBuffer()
                                        [TransportV3::HEADER_SIZE];
                    client->transportMode = requested == TransportV3::MODE_DIRECT &&
                        (client->capabilities & TransportV3::CAP_DIRECT_REPLY) ?
                        TransportV3::MODE_DIRECT : TransportV3::MODE_CREDIT;
                    if (client->transportMode == TransportV3::MODE_DIRECT)
                        while (!client->pollIds.empty()) client->pollIds.pop();
                    else
                        client->directUnacked.clear();
                    echoSendPayloadBuffer()[0] = client->transportMode;
                    sendV3ToClient(client, TunnelHeader::TYPE_MODE_ACK, 1,
                                   TransportV3::FLAG_CONTROL, true, id, seq);
                    syslog(LOG_INFO, "client %s transport mode is now %s",
                           realAddress.format().c_str(),
                           client->transportMode == TransportV3::MODE_DIRECT ?
                           "direct" : "adaptive-credit");
                }
                return true;
            case TunnelHeader::TYPE_TRANSPORT_PING:
                if (client->transportMode == TransportV3::MODE_DIRECT &&
                    directPathFailed(client))
                {
                    client->transportMode = TransportV3::MODE_CREDIT;
                    client->directUnacked.clear();
                    syslog(LOG_WARNING, "direct reply acknowledgements stalled for %s; falling back to adaptive credits",
                           realAddress.format().c_str());
                    echoSendPayloadBuffer()[0] = TransportV3::MODE_CREDIT;
                    sendV3ToClient(client, TunnelHeader::TYPE_MODE_ACK, 1,
                                   TransportV3::FLAG_CONTROL, true, id, seq);
                }
                else
                    sendV3ToClient(client, TunnelHeader::TYPE_TRANSPORT_PING, 0,
                                   TransportV3::FLAG_CONTROL, true, id, seq);
                return true;
            default:
                return true;
        }
    }

    if (header.magic != Client::magic && header.magic != Client::v2Magic &&
        header.magic != Client::v3Magic)
        return false;

    // Legacy protocols use the IPv4 source address as their session key.
    if (!realAddress.isIpv4())
        return false;
    uint32_t realIp = realAddress.ipv4Value();

    ClientData *client = getClientByRealIp(realIp);
    if (client == NULL)
    {
        handleUnknownClient(header, dataLength, realIp, id, seq);
        return true;
    }

    TransportV3::Header transport;
    if (header.type != TunnelHeader::TYPE_CONNECTION_REQUEST &&
        client->state == ClientData::STATE_ESTABLISHED &&
        client->protocolVersion == 3)
    {
        if (!parseTransportHeader(client, dataLength, transport))
            return true;
        processTransportAck(client, transport);

        if (client->autoPoll)
        {
            int requested = transport.creditTarget;
            if (requested < 2)
                requested = 2;
            if (requested > 128)
                requested = 128;
            client->maxPolls = requested;
        }
    }

    bool isControl = header.type == TunnelHeader::TYPE_CONNECTION_REQUEST ||
                     header.type == TunnelHeader::TYPE_DIRECT_PROBE ||
                     header.type == TunnelHeader::TYPE_MODE_SET ||
                     header.type == TunnelHeader::TYPE_TRANSPORT_PING;
    pollReceived(client, id, seq,
                 client->state == ClientData::STATE_ESTABLISHED && !isControl);

    switch (header.type)
    {
        case TunnelHeader::TYPE_CONNECTION_REQUEST:
            if (client->state == ClientData::STATE_CHALLENGE_SENT)
            {
                sendChallenge(client);
                return true;
            }

            while (client->pollIds.size() > 1)
                client->pollIds.pop();

            syslog(LOG_DEBUG, "reconnecting %s", Utility::formatIp(realIp).data());
            sendReset(client);
            removeClient(client);
            return true;
        case TunnelHeader::TYPE_CHALLENGE_RESPONSE:
            if (client->state == ClientData::STATE_CHALLENGE_SENT)
            {
                checkChallenge(client, dataLength);
                return true;
            }
            break;
        case TunnelHeader::TYPE_DATA:
            if (client->state == ClientData::STATE_ESTABLISHED)
            {
                if (dataLength == 0)
                {
                    syslog(LOG_WARNING, "received empty data packet");
                    return true;
                }

                if (client->protocolVersion == 3)
                    handleClientData(
                        client,
                        echoReceivePayloadBuffer() + TransportV3::HEADER_SIZE,
                        dataLength);
                else
                    handleClientData(client, echoReceivePayloadBuffer(),
                                     dataLength);
                return true;
            }
            break;
        case TunnelHeader::TYPE_POLL:
            return true;
        case TunnelHeader::TYPE_DIRECT_PROBE:
            if (client->state == ClientData::STATE_ESTABLISHED &&
                client->protocolVersion == 3 && client->autoPoll &&
                (client->capabilities & TransportV3::CAP_DIRECT_REPLY))
            {
                sendDirectProbeReplies(client, id, seq);
                return true;
            }
            break;
        case TunnelHeader::TYPE_MODE_SET:
            if (client->state == ClientData::STATE_ESTABLISHED &&
                client->protocolVersion == 3 && dataLength == 1)
            {
                uint8_t requested = (uint8_t)echoReceivePayloadBuffer()
                                    [TransportV3::HEADER_SIZE];
                if (requested == TransportV3::MODE_DIRECT &&
                    (client->capabilities & TransportV3::CAP_DIRECT_REPLY))
                {
                    client->transportMode = TransportV3::MODE_DIRECT;
                    while (!client->pollIds.empty())
                        client->pollIds.pop();
                }
                else
                    client->transportMode = TransportV3::MODE_CREDIT;

                if (client->transportMode == TransportV3::MODE_CREDIT)
                    client->directUnacked.clear();
                echoSendPayloadBuffer()[0] = client->transportMode;
                sendV3ToClient(client, TunnelHeader::TYPE_MODE_ACK, 1,
                               TransportV3::FLAG_CONTROL, true, id, seq);
                syslog(LOG_INFO, "client %s transport mode is now %s",
                       Utility::formatIp(realIp).c_str(),
                       client->transportMode == TransportV3::MODE_DIRECT ?
                       "direct" : "adaptive-credit");
                return true;
            }
            break;
        case TunnelHeader::TYPE_TRANSPORT_PING:
            if (client->state == ClientData::STATE_ESTABLISHED &&
                client->protocolVersion == 3)
            {
                if (client->transportMode == TransportV3::MODE_DIRECT &&
                    directPathFailed(client))
                {
                    client->transportMode = TransportV3::MODE_CREDIT;
                    client->directUnacked.clear();
                    syslog(LOG_WARNING, "direct reply acknowledgements stalled for %s; falling back to adaptive credits",
                           Utility::formatIp(realIp).c_str());
                    echoSendPayloadBuffer()[0] = TransportV3::MODE_CREDIT;
                    sendV3ToClient(client, TunnelHeader::TYPE_MODE_ACK, 1,
                                   TransportV3::FLAG_CONTROL, true, id, seq);
                }
                else
                {
                    sendV3ToClient(client, TunnelHeader::TYPE_TRANSPORT_PING,
                                   0, TransportV3::FLAG_CONTROL, true,
                                   id, seq);
                }
                return true;
            }
            break;
        default:
            break;
    }

    syslog(LOG_DEBUG, "invalid packet from: %s, type: %d, state: %d",
           Utility::formatIp(realIp).data(), header.type, client->state);

    return true;
}

Server::ClientData *Server::getClientByTunnelIp(uint32_t ip)
{
    ClientIpMap::iterator it = clientTunnelIpMap.find(ip);
    if (it == clientTunnelIpMap.end())
        return NULL;

    return &*it->second;
}

Server::ClientData *Server::getClientByRealIp(uint32_t ip)
{
    ClientIpMap::iterator it = clientRealIpMap.find(ip);
    if (it == clientRealIpMap.end())
        return NULL;

    return &*it->second;
}

Server::ClientData *Server::getClientByReceiverIndex(uint32_t index)
{
    ClientIpMap::iterator it = clientReceiverIndexMap.find(index);
    if (it == clientReceiverIndexMap.end())
        return NULL;

    return &*it->second;
}

Server::ClientData *Server::getClientByDeviceId(const string &deviceId, ClientData *except)
{
    if (deviceId.empty())
        return NULL;

    for (ClientList::iterator it = clientList.begin(); it != clientList.end(); ++it)
    {
        if (&*it != except && it->deviceId == deviceId)
            return &*it;
    }
    return NULL;
}

void Server::handleClientData(ClientData *sourceClient, const char *packet,
                              int packetLength)
{
    // Parse only the invariant IPv4 header fields. The tunnel carries IPv4
    // inner packets, but options and fragmentation are still valid.
    if (packetLength < 20 || ((const uint8_t *)packet)[0] >> 4 != 4)
    {
        syslog(LOG_WARNING, "discarding malformed inner packet from peer %s",
               sourceClient->deviceId.c_str());
        return;
    }
    int headerLength = (((const uint8_t *)packet)[0] & 15) * 4;
    if (headerLength < 20 || headerLength > packetLength)
    {
        syslog(LOG_WARNING, "discarding malformed inner packet from peer %s",
               sourceClient->deviceId.c_str());
        return;
    }

    uint32_t sourceIp;
    uint32_t destIp;
    memcpy(&sourceIp, packet + 12, sizeof(sourceIp));
    memcpy(&destIp, packet + 16, sizeof(destIp));
    sourceIp = ntohl(sourceIp);
    destIp = ntohl(destIp);

    ClientData *target = getClientByTunnelIp(destIp);
    if (target != NULL && target->state == ClientData::STATE_ESTABLISHED)
    {
        // Direct peer forwarding is independent of Linux ip_forward and the
        // host firewall. Authenticate the inner source before bypassing the
        // kernel so one peer cannot impersonate another VPN address.
        if (sourceIp != sourceClient->tunnelIp)
        {
            syslog(LOG_WARNING,
                   "discarding spoofed peer packet from %s claiming %s",
                   sourceClient->deviceId.c_str(),
                   Utility::formatIp(sourceIp).c_str());
            return;
        }
        memcpy(echoSendPayloadBuffer(), packet, packetLength);
        sendEchoToClient(target, TunnelHeader::TYPE_DATA, packetLength);
        return;
    }

    tun.write(packet, packetLength);
}

void Server::handleTunData(int dataLength, uint32_t, uint32_t destIp)
{
    if (destIp == network + 255) // ignore broadcasts
        return;

    ClientData *client = getClientByTunnelIp(destIp);

    if (client == NULL || client->state != ClientData::STATE_ESTABLISHED)
    {
        syslog(LOG_DEBUG, "data received for unavailable client %s\n",
               Utility::formatIp(destIp).data());
        return;
    }

    sendEchoToClient(client, TunnelHeader::TYPE_DATA, dataLength);
}

void Server::pollReceived(ClientData *client, uint16_t echoId, uint16_t echoSeq,
                          bool servePending)
{
    unsigned int maxSavedPolls = client->maxPolls != 0 ? client->maxPolls : 1;

    client->lastEcho = ClientData::EchoId(echoId, echoSeq);
    client->haveLastEcho = true;

    if (client->transportMode == TransportV3::MODE_CREDIT ||
        client->protocolVersion < 3)
    {
        client->pollIds.push(ClientData::EchoId(echoId, echoSeq));
        if (client->pollIds.size() > maxSavedPolls)
            client->pollIds.pop();
    }
    DEBUG_ONLY(cout << "poll -> " << client->pollIds.size() << endl);

    if (servePending && client->pendingPackets.size() > 0)
    {
        // Report that this credit found queued work even when it consumes the
        // last packet. Otherwise a continuously busy one-packet queue looks
        // idle and the adaptive window never grows beyond its startup value.
        client->backlogHint = client->pendingPackets.size();
        Packet &packet = client->pendingPackets.front();
        const TunnelHeader::Type packetType = packet.type;
        const int packetLength = packet.data.size();
        memcpy(echoSendPayloadBuffer(), &packet.data[0], packetLength);
        client->pendingPackets.pop();

        DEBUG_ONLY(cout << "pending packet: " << packetLength << " bytes\n");
        sendEchoToClient(client, packetType, packetLength);
    }

    client->lastActivity = now;
    if (!client->deviceId.empty())
    {
        LeaseMap::iterator lease = leases.find(client->deviceId);
        if (lease != leases.end())
        {
            lease->second.lastSeen = time(NULL);
            lease->second.realIp = client->realIp;
            lease->second.realAddressText = client->realAddress.format();
        }
    }
}

void Server::sendEchoToClient(ClientData *client, TunnelHeader::Type type, int dataLength)
{
    if (client->protocolVersion >= 3 &&
        client->state == ClientData::STATE_ESTABLISHED)
    {
        sendV3ToClient(client, type, dataLength, TransportV3::FLAG_NONE,
                       false, 0, 0);
        return;
    }

    if (client->maxPolls == 0)
    {
        const TunnelHeader::Magic &responseMagic =
            client->protocolVersion == 4 ? v4Magic :
            (client->protocolVersion == 3 ? v3Magic :
            (client->protocolVersion == 2 ? v2Magic : magic));
        sendEcho(responseMagic, type, dataLength,
                 client->realAddress, true, client->pollIds.front().id,
                 client->pollIds.front().seq);
        return;
    }

    if (client->pollIds.size() != 0)
    {
        ClientData::EchoId echoId = client->pollIds.front();
        client->pollIds.pop();

        DEBUG_ONLY(cout << "sending -> " << client->pollIds.size() << endl);
        const TunnelHeader::Magic &responseMagic =
            client->protocolVersion == 4 ? v4Magic :
            (client->protocolVersion == 3 ? v3Magic :
            (client->protocolVersion == 2 ? v2Magic : magic));
        sendEcho(responseMagic, type, dataLength,
                 client->realAddress, true, echoId.id, echoId.seq);
        return;
    }

    if (client->pendingPackets.size() >= MAX_BUFFERED_PACKETS)
    {
        client->pendingPackets.pop();
        syslog(LOG_WARNING, "packet to %s dropped",
               Utility::formatIp(client->tunnelIp).data());
    }

    DEBUG_ONLY(cout << "packet queued: " << dataLength << " bytes\n");

    client->pendingPackets.push(Packet());
    Packet &packet = client->pendingPackets.back();
    packet.type = type;
    packet.data.resize(dataLength);
    if (dataLength > 0)
        memcpy(&packet.data[0], echoSendPayloadBuffer(), dataLength);
}

void Server::sendV3ToClient(ClientData *client, TunnelHeader::Type type,
                            int dataLength, uint8_t flags, bool forceEcho,
                            uint16_t echoId, uint16_t echoSeq)
{
    ClientData::EchoId target;
    bool direct = forceEcho ||
                  client->transportMode == TransportV3::MODE_DIRECT;

    if (forceEcho)
        target = ClientData::EchoId(echoId, echoSeq);
    else if (direct)
    {
        if (!client->haveLastEcho)
            return;
        target = client->lastEcho;
    }
    else if (!client->pollIds.empty())
    {
        target = client->pollIds.front();
        client->pollIds.pop();
    }
    else
    {
        if (client->pendingPackets.size() >= MAX_V3_BUFFERED_PACKETS)
        {
            client->pendingPackets.pop();
            syslog(LOG_WARNING, "packet to %s dropped",
                   Utility::formatIp(client->tunnelIp).c_str());
        }

        client->pendingPackets.push(Packet());
        Packet &packet = client->pendingPackets.back();
        packet.type = type;
        packet.data.resize(dataLength);
        if (dataLength > 0)
            memcpy(&packet.data[0], echoSendPayloadBuffer(), dataLength);
        return;
    }

    char *payload = echoSendPayloadBuffer();
    if (dataLength > 0)
        memmove(payload + TransportV3::HEADER_SIZE, payload, dataLength);

    TransportV3::Header transport;
    transport.flags = flags | (direct ? TransportV3::FLAG_DIRECT : 0);
    transport.mode = client->transportMode;
    transport.creditTarget = (uint8_t)client->maxPolls;
    transport.sessionId = client->sessionId;
    transport.txSequence = ++client->nextTransportSequence;
    if (transport.txSequence == 0)
        transport.txSequence = ++client->nextTransportSequence;
    transport.ackSequence = client->receivedSequences.ackSequence();
    transport.ackBits = client->receivedSequences.ackBits();
    unsigned int queuedPackets = client->pendingPackets.size();
    if (client->backlogHint > queuedPackets)
        queuedPackets = client->backlogHint;
    transport.queuedPackets = queuedPackets > 65535 ? 65535 :
                              (uint16_t)queuedPackets;
    client->backlogHint = 0;
    transport.timestamp = (uint16_t)((now.milliseconds() / 16) & 0xffff);
    TransportV3::encode(payload, transport);

    int wireLength = dataLength + TransportV3::HEADER_SIZE;
    const TunnelHeader::Magic *wireMagic = &v3Magic;
    if (client->protocolVersion == 4)
    {
        TunnelHeader ad;
        ad.magic = v4Magic;
        ad.type = type;
        std::vector<uint8_t> packet;
        if (!client->secureTransport.seal((const uint8_t *)&ad, sizeof(ad),
                                          (const uint8_t *)payload,
                                          wireLength, packet))
            return;
        memcpy(payload, &packet[0], packet.size());
        wireLength = packet.size();
        wireMagic = &v4Magic;
    }

    sendEcho(*wireMagic, type, wireLength,
             client->realAddress, true, target.id, target.seq);

    if (!forceEcho && client->transportMode == TransportV3::MODE_DIRECT &&
        type == TunnelHeader::TYPE_DATA)
        client->directUnacked[transport.txSequence] = now;
}

bool Server::openV4Packet(ClientData *client, const TunnelHeader &header,
                          int &dataLength, const Echo::Address &realAddress)
{
    std::vector<uint8_t> plain;
    if (!client->secureTransport.open((const uint8_t *)&header, sizeof(header),
                                      (const uint8_t *)echoReceivePayloadBuffer(),
                                      dataLength, plain))
        return false;
    if (!plain.empty())
        memcpy(echoReceivePayloadBuffer(), &plain[0], plain.size());
    dataLength = plain.size();

    // The receiver index and AEAD authenticate this peer, so a changed source
    // address is safe to adopt after (and only after) successful decryption.
    if (client->realAddress != realAddress)
    {
        syslog(LOG_INFO, "secure peer %s roamed from %s to %s",
               client->deviceId.c_str(), client->realAddress.format().c_str(),
               realAddress.format().c_str());
        client->realAddress = realAddress;
        client->realIp = realAddress.isIpv4() ? realAddress.ipv4Value() : 0;
        updateLease(client, true);
    }
    return true;
}

void Server::sendV4RawToClient(ClientData *client, TunnelHeader::Type type,
                               const char *data, int dataLength,
                               uint16_t echoId, uint16_t echoSeq)
{
    TunnelHeader ad;
    ad.magic = v4Magic;
    ad.type = type;
    std::vector<uint8_t> packet;
    if (!client->secureTransport.seal((const uint8_t *)&ad, sizeof(ad),
                                      (const uint8_t *)data, dataLength, packet))
        return;
    memcpy(echoSendPayloadBuffer(), &packet[0], packet.size());
    sendEcho(v4Magic, type, packet.size(), client->realAddress, true,
             echoId, echoSeq);
}

void Server::sendDirectProbeReplies(ClientData *client, uint16_t echoId,
                                    uint16_t echoSeq)
{
    for (int i = 0; i < 3; ++i)
        sendV3ToClient(client, TunnelHeader::TYPE_DIRECT_PROBE_REPLY, 0,
                       TransportV3::FLAG_CONTROL, true, echoId, echoSeq);
}

bool Server::parseTransportHeader(ClientData *client, int &dataLength,
                                  TransportV3::Header &transport)
{
    if (!TransportV3::decode(echoReceivePayloadBuffer(), dataLength,
                             transport) ||
        transport.sessionId != client->sessionId)
    {
        syslog(LOG_WARNING, "discarding invalid transport v3 packet from %s",
               Utility::formatIp(client->realIp).c_str());
        return false;
    }
    if (!client->receivedSequences.accept(transport.txSequence))
        return false;

    dataLength -= TransportV3::HEADER_SIZE;
    return true;
}

void Server::processTransportAck(ClientData *client,
                                 const TransportV3::Header &transport)
{
    std::map<uint32_t, Time>::iterator it = client->directUnacked.begin();
    while (it != client->directUnacked.end())
    {
        std::map<uint32_t, Time>::iterator current = it++;
        bool beyondAckWindow = transport.ackSequence != 0 &&
                               TransportV3::sequenceAfter(
                                   transport.ackSequence, current->first) &&
                               transport.ackSequence - current->first > 32;
        if (beyondAckWindow ||
            TransportV3::acknowledged(current->first,
                                      transport.ackSequence,
                                      transport.ackBits))
            client->directUnacked.erase(current);
    }
}

bool Server::directPathFailed(ClientData *client) const
{
    if ((int)client->directUnacked.size() < DIRECT_UNACKED_LIMIT)
        return false;

    for (std::map<uint32_t, Time>::const_iterator it =
             client->directUnacked.begin();
         it != client->directUnacked.end(); ++it)
    {
        if (now > it->second + Time(DIRECT_ACK_TIMEOUT_MS))
            return true;
    }
    return false;
}

void Server::releaseTunnelIp(uint32_t tunnelIp, const string &deviceId)
{
    usedIps.erase(tunnelIp);
    if (!deviceId.empty())
    {
        LeaseMap::iterator lease = leases.find(deviceId);
        if (lease != leases.end() && lease->second.tunnelIp == tunnelIp)
        {
            lease->second.active = false;
            lease->second.lastSeen = time(NULL);
            saveLeases();
        }
    }
}

void Server::handleTimeout()
{
    ClientList::iterator it = clientList.begin();
    while (it != clientList.end())
    {
        ClientData &client = *it++;

        if (client.lastActivity + KEEP_ALIVE_INTERVAL * 2 < now)
        {
            syslog(LOG_DEBUG, "client %s timed out\n",
                   Utility::formatIp(client.realIp).data());
            removeClient(&client);
        }
    }

    saveLeases();
    setTimeout(KEEP_ALIVE_INTERVAL);
}

uint32_t Server::reserveTunnelIp(uint32_t desiredIp, const string &deviceId)
{
    if (!deviceId.empty())
    {
        LeaseMap::iterator existing = leases.find(deviceId);
        if (existing != leases.end() && !usedIps.count(existing->second.tunnelIp))
        {
            usedIps.insert(existing->second.tunnelIp);
            return existing->second.tunnelIp;
        }
    }

    if (desiredIp > network + 1 && desiredIp < network + 255 &&
        !usedIps.count(desiredIp) && !leaseIpMap.count(desiredIp))
    {
        usedIps.insert(desiredIp);
        return desiredIp;
    }

    bool ipAvailable = false;

    for (int i = 0; i < 255 - FIRST_ASSIGNED_IP_OFFSET; i++)
    {
        latestAssignedIpOffset++;
        if (latestAssignedIpOffset == 255)
            latestAssignedIpOffset = FIRST_ASSIGNED_IP_OFFSET;

        uint32_t candidate = network + latestAssignedIpOffset;
        if (!usedIps.count(candidate) && !leaseIpMap.count(candidate))
        {
            ipAvailable = true;
            break;
        }
    }

    uint32_t assignedIp = network + latestAssignedIpOffset;
    if (!ipAvailable)
    {
        LeaseMap::iterator oldest = leases.end();
        for (LeaseMap::iterator it = leases.begin(); it != leases.end(); ++it)
        {
            if (it->second.tunnelIp >= network + FIRST_ASSIGNED_IP_OFFSET &&
                it->second.tunnelIp < network + 255 &&
                !it->second.active && !usedIps.count(it->second.tunnelIp) &&
                (oldest == leases.end() || it->second.lastSeen < oldest->second.lastSeen))
                oldest = it;
        }

        if (oldest == leases.end())
            return 0;

        assignedIp = oldest->second.tunnelIp;
        leaseIpMap.erase(assignedIp);
        leases.erase(oldest);
    }

    usedIps.insert(assignedIp);
    return assignedIp;
}

void Server::updateLease(ClientData *client, bool active)
{
    if (client->deviceId.empty())
        return;

    Lease &lease = leases[client->deviceId];
    if (lease.tunnelIp != 0 && lease.tunnelIp != client->tunnelIp)
        leaseIpMap.erase(lease.tunnelIp);

    lease.deviceId = client->deviceId;
    lease.tunnelIp = client->tunnelIp;
    lease.lastSeen = time(NULL);
    lease.active = active;
    lease.realIp = client->realIp;
    lease.realAddressText = client->realAddress.format();
    leaseIpMap[lease.tunnelIp] = lease.deviceId;
    saveLeases();
}

void Server::loadLeases()
{
    leases.clear();
    leaseIpMap.clear();

    std::ifstream input(leaseFile.c_str());
    string deviceId;
    uint32_t tunnelIp;
    long lastSeen;
    int active;
    string realAddressText;
    while (input >> deviceId >> tunnelIp >> lastSeen >> active >> realAddressText)
    {
        if (!Utility::isDeviceId(deviceId) ||
            tunnelIp <= network + 1 || tunnelIp >= network + 255)
            continue;

        Lease lease;
        lease.deviceId = Utility::normalizeDeviceId(deviceId);
        lease.tunnelIp = tunnelIp;
        lease.lastSeen = (time_t)lastSeen;
        lease.active = false;
        char *end = NULL;
        unsigned long legacyRealIp = strtoul(realAddressText.c_str(), &end, 10);
        if (end != realAddressText.c_str() && *end == '\0' &&
            legacyRealIp <= 0xfffffffful)
        {
            lease.realIp = (uint32_t)legacyRealIp;
            lease.realAddressText = Utility::formatIp(lease.realIp);
        }
        else
        {
            lease.realIp = 0;
            lease.realAddressText = realAddressText;
        }
        leases[lease.deviceId] = lease;
        leaseIpMap[lease.tunnelIp] = lease.deviceId;
    }
    saveLeases();
}

void Server::saveLeases()
{
    if (leaseFd == -1)
        return;

    std::ostringstream output;
    for (LeaseMap::const_iterator it = leases.begin(); it != leases.end(); ++it)
    {
        const Lease &lease = it->second;
        output << lease.deviceId << ' ' << lease.tunnelIp << ' '
               << (long)lease.lastSeen << ' ' << (lease.active ? 1 : 0)
               << ' ' << (lease.realAddressText.empty() ?
                           Utility::formatIp(lease.realIp) :
                           lease.realAddressText) << '\n';
    }

    string data = output.str();
    if (lseek(leaseFd, 0, SEEK_SET) == -1 || ftruncate(leaseFd, 0) == -1)
    {
        syslog(LOG_ERR, "could not save lease file: %s", strerror(errno));
        return;
    }

    string::size_type offset = 0;
    while (offset < data.size())
    {
        ssize_t written = write(leaseFd, data.data() + offset, data.size() - offset);
        if (written <= 0)
        {
            syslog(LOG_ERR, "could not save lease file: %s", strerror(errno));
            return;
        }
        offset += written;
    }
    fsync(leaseFd);
}

int Server::listPeers(const string &leaseFile, bool json)
{
    std::ifstream input(leaseFile.c_str());
    if (!input)
    {
        std::cerr << "could not open lease file: " << leaseFile << std::endl;
        return 1;
    }

    if (json)
        cout << "[";
    else
        cout << std::left << std::setw(34) << "DEVICE ID"
             << std::setw(17) << "TUNNEL IP"
             << std::setw(41) << "REAL IP"
             << std::setw(10) << "STATE"
             << "LAST SEEN" << endl;

    string deviceId;
    uint32_t tunnelIp;
    long lastSeen;
    int active;
    string realAddressText;
    bool first = true;
    while (input >> deviceId >> tunnelIp >> lastSeen >> active >> realAddressText)
    {
        char *end = NULL;
        unsigned long legacyRealIp = strtoul(realAddressText.c_str(), &end, 10);
        if (end != realAddressText.c_str() && *end == '\0' &&
            legacyRealIp <= 0xfffffffful)
            realAddressText = Utility::formatIp((uint32_t)legacyRealIp);
        char formattedTime[32] = "-";
        time_t timestamp = (time_t)lastSeen;
        struct tm *local = localtime(&timestamp);
        if (local != NULL)
            strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d %H:%M:%S", local);

        if (json)
        {
            if (!first) cout << ',';
            cout << "{\"device_id\":\"" << deviceId
                 << "\",\"tunnel_ip\":\"" << Utility::formatIp(tunnelIp)
                 << "\",\"real_ip\":\"" << realAddressText
                 << "\",\"online\":" << (active ? "true" : "false")
                 << ",\"last_seen\":" << lastSeen << '}';
            first = false;
        }
        else
            cout << std::left << std::setw(34) << deviceId
                 << std::setw(17) << Utility::formatIp(tunnelIp)
                 << std::setw(41) << realAddressText
                 << std::setw(10) << (active ? "online" : "offline")
                 << formattedTime << endl;
    }
    if (json)
        cout << "]" << endl;
    return 0;
}

void Server::run()
{
    setTimeout(KEEP_ALIVE_INTERVAL);

    Worker::run();
}
