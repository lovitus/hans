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
#include <time.h>

using std::string;
using std::cout;
using std::endl;

#define FIRST_ASSIGNED_IP_OFFSET 100

const Worker::TunnelHeader::Magic Server::magic("hans");
const Worker::TunnelHeader::Magic Server::v2Magic("hns2");

Server::Server(int tunnelMtu, const string *deviceName, const string &passphrase,
               uint32_t network, bool answerEcho, uid_t uid, gid_t gid, int pollTimeout,
               const string &leaseFile)
    : Worker(tunnelMtu, deviceName, answerEcho, uid, gid), auth(passphrase)
{
    this->network = network & 0xffffff00;
    this->pollTimeout = pollTimeout;
    this->latestAssignedIpOffset = FIRST_ASSIGNED_IP_OFFSET - 1;
    this->leaseFile = leaseFile;
    this->leaseFd = -1;

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
    for (LeaseMap::iterator it = leases.begin(); it != leases.end(); ++it)
        it->second.active = false;
    saveLeases();
    if (leaseFd != -1)
        close(leaseFd);
}

void Server::handleUnknownClient(const TunnelHeader &header, int dataLength, uint32_t realIp, uint16_t echoId, uint16_t echoSeq)
{
    ClientData client;
    client.realIp = realIp;
    client.maxPolls = 1;
    client.protocolV2 = header.magic == Client::v2Magic;

    pollReceived(&client, echoId, echoSeq, false);

    if (header.type != TunnelHeader::TYPE_CONNECTION_REQUEST ||
        (client.protocolV2 && dataLength != sizeof(ClientConnectDataV2)) ||
        (!client.protocolV2 && dataLength != sizeof(ClientConnectData)) ||
        (dataLength != sizeof(ClientConnectData) &&
         dataLength != sizeof(ClientConnectDataV2)))
    {
        syslog(LOG_DEBUG, "invalid request (type %d) from %s", header.type,
               Utility::formatIp(realIp).c_str());
        sendReset(&client);
        return;
    }

    ClientConnectData *connectData = (ClientConnectData *)echoReceivePayloadBuffer();
    if (dataLength == sizeof(ClientConnectDataV2))
    {
        ClientConnectDataV2 *connectDataV2 =
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

    client.maxPolls = connectData->maxPolls;
    client.state = ClientData::STATE_NEW;
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

    ClientList::iterator it = clientRealIpMap[client->realIp];

    clientRealIpMap.erase(client->realIp);
    clientTunnelIpMap.erase(client->tunnelIp);

    clientList.erase(it);
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

    uint32_t *ip = (uint32_t *)echoSendPayloadBuffer();
    *ip = htonl(client->tunnelIp);

    sendEchoToClient(client, TunnelHeader::TYPE_CONNECTION_ACCEPT, sizeof(uint32_t));

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

bool Server::handleEchoData(const TunnelHeader &header, int dataLength, uint32_t realIp, bool reply, uint16_t id, uint16_t seq)
{
    if (reply)
        return false;

    if (header.magic != Client::magic && header.magic != Client::v2Magic)
        return false;

    ClientData *client = getClientByRealIp(realIp);
    if (client == NULL)
    {
        handleUnknownClient(header, dataLength, realIp, id, seq);
        return true;
    }

    pollReceived(client, id, seq,
                 client->state == ClientData::STATE_ESTABLISHED &&
                 header.type != TunnelHeader::TYPE_CONNECTION_REQUEST);

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

                sendToTun(dataLength);
                return true;
            }
            break;
        case TunnelHeader::TYPE_POLL:
            return true;
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

    client->pollIds.push(ClientData::EchoId(echoId, echoSeq));
    if (client->pollIds.size() > maxSavedPolls)
        client->pollIds.pop();
    DEBUG_ONLY(cout << "poll -> " << client->pollIds.size() << endl);

    if (servePending && client->pendingPackets.size() > 0)
    {
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
        }
    }
}

void Server::sendEchoToClient(ClientData *client, TunnelHeader::Type type, int dataLength)
{
    if (client->maxPolls == 0)
    {
        sendEcho(client->protocolV2 ? v2Magic : magic, type, dataLength,
                 client->realIp, true, client->pollIds.front().id,
                 client->pollIds.front().seq);
        return;
    }

    if (client->pollIds.size() != 0)
    {
        ClientData::EchoId echoId = client->pollIds.front();
        client->pollIds.pop();

        DEBUG_ONLY(cout << "sending -> " << client->pollIds.size() << endl);
        sendEcho(client->protocolV2 ? v2Magic : magic, type, dataLength,
                 client->realIp, true, echoId.id, echoId.seq);
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
    memcpy(&packet.data[0], echoReceivePayloadBuffer(), dataLength);
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
    uint32_t realIp;
    while (input >> deviceId >> tunnelIp >> lastSeen >> active >> realIp)
    {
        if (!Utility::isDeviceId(deviceId) ||
            tunnelIp <= network + 1 || tunnelIp >= network + 255)
            continue;

        Lease lease;
        lease.deviceId = Utility::normalizeDeviceId(deviceId);
        lease.tunnelIp = tunnelIp;
        lease.lastSeen = (time_t)lastSeen;
        lease.active = false;
        lease.realIp = realIp;
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
               << ' ' << lease.realIp << '\n';
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

int Server::listPeers(const string &leaseFile)
{
    std::ifstream input(leaseFile.c_str());
    if (!input)
    {
        std::cerr << "could not open lease file: " << leaseFile << std::endl;
        return 1;
    }

    cout << std::left << std::setw(34) << "DEVICE ID"
         << std::setw(17) << "TUNNEL IP"
         << std::setw(17) << "REAL IP"
         << std::setw(10) << "STATE"
         << "LAST SEEN" << endl;

    string deviceId;
    uint32_t tunnelIp;
    long lastSeen;
    int active;
    uint32_t realIp;
    while (input >> deviceId >> tunnelIp >> lastSeen >> active >> realIp)
    {
        char formattedTime[32] = "-";
        time_t timestamp = (time_t)lastSeen;
        struct tm *local = localtime(&timestamp);
        if (local != NULL)
            strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d %H:%M:%S", local);

        cout << std::left << std::setw(34) << deviceId
             << std::setw(17) << Utility::formatIp(tunnelIp)
             << std::setw(17) << Utility::formatIp(realIp)
             << std::setw(10) << (active ? "online" : "offline")
             << formattedTime << endl;
    }
    return 0;
}

void Server::run()
{
    setTimeout(KEEP_ALIVE_INTERVAL);

    Worker::run();
}
