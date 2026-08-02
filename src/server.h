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

#ifndef SERVER_H
#define SERVER_H

#include "worker.h"
#include "auth.h"
#include "config.h"
#include "transport.h"
#include "kernel_echo_guard.h"
#include "secure.h"

#include <map>
#include <queue>
#include <vector>
#include <list>
#include <set>
#include <string>
#include <time.h>

class Server : public Worker
{
public:
    Server(int tunnelMtu, const std::string *deviceName, const std::string &passphrase,
           uint32_t network, bool answerEcho, uid_t uid, gid_t gid, int pollTimeout,
           const std::string &leaseFile,
           const std::string &identityFile = std::string(),
           bool requireV4 = false, bool requireV5 = false);
    virtual ~Server();

    static int listPeers(const std::string &leaseFile, bool json = false);

    struct ClientConnectData
    {
        uint8_t maxPolls;
        uint32_t desiredIp;
    };

    struct ClientConnectDataV2
    {
        ClientConnectData legacy;
        char deviceId[DEVICE_ID_HEX_SIZE];
    };

    struct ClientConnectDataV3
    {
        ClientConnectDataV2 v2;
        uint8_t capabilities;
        uint8_t minimumPolls;
        uint8_t maximumPolls;
        uint8_t reserved;
    };

    static const TunnelHeader::Magic magic;
    static const TunnelHeader::Magic v2Magic;
    static const TunnelHeader::Magic v3Magic;
    static const TunnelHeader::Magic v4Magic;

protected:
    struct Packet
    {
        TunnelHeader::Type type;
        std::vector<char> data;
    };

    struct ClientData
    {
        enum State
        {
            STATE_NEW,
            STATE_CHALLENGE_SENT,
            STATE_ESTABLISHED
        };

        struct EchoId
        {
            EchoId() { id = 0; seq = 0; }
            EchoId(uint16_t id, uint16_t seq) { this->id = id; this->seq = seq; }

            uint16_t id;
            uint16_t seq;
        };

        uint32_t realIp;
        Echo::Address realAddress;
        uint32_t tunnelIp;
        uint32_t desiredIp;
        std::string deviceId;
        int protocolVersion;
        int capabilities;
        bool autoPoll;
        int kernelEchoFamily;
        uint8_t transportMode;
        uint32_t sessionId;
        uint32_t localReceiverIndex;
        uint32_t peerReceiverIndex;
        NoiseHandshake *secureHandshake;
        SecureTransport secureTransport;
        uint32_t nextTransportSequence;
        SequenceTracker receivedSequences;
        TransportReorderBuffer reorderBuffer;
        Time lastTransportTelemetry;
        EchoId lastEcho;
        bool haveLastEcho;
        DirectAckTracker directUnacked;
        unsigned int backlogHint;

        std::queue<Packet> pendingPackets;

        int maxPolls;
        std::queue<EchoId> pollIds;
        Time lastActivity;

        State state;

        Auth::Challenge challenge;
    };

    typedef std::list<ClientData> ClientList;
    typedef std::map<uint32_t, ClientList::iterator> ClientIpMap;

    struct Lease
    {
        std::string deviceId;
        uint32_t tunnelIp;
        time_t lastSeen;
        bool active;
        uint32_t realIp;
        std::string realAddressText;
    };

    typedef std::map<std::string, Lease> LeaseMap;
    typedef std::map<uint32_t, std::string> LeaseIpMap;

    virtual bool handleEchoData(const TunnelHeader &header, int dataLength,
                                const Echo::Address &realAddress, bool reply,
                                uint16_t id, uint16_t seq);
    virtual void handleTunData(int dataLength, uint32_t sourceIp, uint32_t destIp);
    virtual void handleTimeout();
    virtual int idleIntervalMilliseconds() const;
    virtual void handleIdle();

    virtual void run();

    void serveTun(ClientData *client);

    void handleUnknownClient(const TunnelHeader &header, int dataLength, uint32_t realIp, uint16_t echoId, uint16_t echoSeq);
    void handleV4HandshakeInit(const TunnelHeader &header, int dataLength,
                               const Echo::Address &realAddress,
                               uint16_t echoId, uint16_t echoSeq);
    void handleV4HandshakeFinish(const TunnelHeader &header, int dataLength,
                                 const Echo::Address &realAddress,
                                 uint16_t echoId, uint16_t echoSeq);
    void handleV5HandshakeInit(const std::vector<uint8_t> &plain,
                               const Echo::Address &realAddress,
                               uint16_t echoId, uint16_t echoSeq);
    void handleV5HandshakeFinish(const std::vector<uint8_t> &plain,
                                 const Echo::Address &realAddress,
                                 uint16_t echoId, uint16_t echoSeq);
    void completeSecureHandshake(ClientData *client,
                                 const std::vector<uint8_t> &decoded,
                                 const Echo::Address &realAddress,
                                 uint16_t echoId, uint16_t echoSeq);
    void removeClient(ClientData *client);

    void sendChallenge(ClientData *client);
    void checkChallenge(ClientData *client, int dataLength);
    void sendReset(ClientData *client);

    void sendEchoToClient(ClientData *client, TunnelHeader::Type type, int dataLength);
    void sendV3ToClient(ClientData *client, TunnelHeader::Type type,
                        int dataLength, uint8_t flags, bool forceEcho,
                        uint16_t echoId, uint16_t echoSeq);
    void sendDirectProbeReplies(ClientData *client, uint16_t echoId,
                                uint16_t echoSeq);
    void handleClientData(ClientData *sourceClient, const char *packet,
                          int packetLength);
    void deliverReorderedPackets(ClientData *client,
                                 std::vector<std::vector<char> > &packets);
    void logTransportTelemetry(ClientData *client);
    bool parseTransportHeader(ClientData *client, int &dataLength,
                              TransportV3::Header &transport);
    bool openV4Packet(ClientData *client, const TunnelHeader &header,
                      int &dataLength, const Echo::Address &realAddress);
    bool openV5Packet(ClientData *client, TunnelHeader::Type &type,
                      int &dataLength, const Echo::Address &realAddress);
    void sendV4RawToClient(ClientData *client, TunnelHeader::Type type,
                           const char *data, int dataLength,
                           uint16_t echoId, uint16_t echoSeq);
    void sendV5RawToClient(ClientData *client, TunnelHeader::Type type,
                           const char *data, int dataLength,
                           uint16_t echoId, uint16_t echoSeq);
    bool handleSecureClientPacket(ClientData *client,
                                  TunnelHeader::Type type, int dataLength,
                                  const Echo::Address &realAddress,
                                  uint16_t id, uint16_t seq);
    void processTransportAck(ClientData *client,
                             const TransportV3::Header &transport);
    bool directPathFailed(ClientData *client) const;

    void pollReceived(ClientData *client, uint16_t echoId, uint16_t echoSeq,
                      bool servePending);

    uint32_t reserveTunnelIp(uint32_t desiredIp, const std::string &deviceId);
    void releaseTunnelIp(uint32_t tunnelIp, const std::string &deviceId);
    void loadLeases();
    void saveLeases();
    void updateLease(ClientData *client, bool active);

    ClientData *getClientByTunnelIp(uint32_t ip);
    ClientData *getClientByRealIp(uint32_t ip);
    ClientData *getClientByReceiverIndex(uint32_t index);
    ClientData *getClientByDeviceId(const std::string &deviceId, ClientData *except);

    Auth auth;

    uint32_t network;
    std::set<uint32_t> usedIps;
    uint32_t latestAssignedIpOffset;
    std::string leaseFile;
    int leaseFd;
    LeaseMap leases;
    LeaseIpMap leaseIpMap;

    Time pollTimeout;

    ClientList clientList;
    ClientIpMap clientRealIpMap;
    ClientIpMap clientTunnelIpMap;
    ClientIpMap clientReceiverIndexMap;
    SecureIdentity secureIdentity;
    uint8_t securePsk[32];
    uint8_t handshakeKeyV5[32];
    bool requireV4;
    bool requireV5;
    KernelEchoGuard kernelEchoGuard;
    KernelEchoGuard kernelEchoGuard6;
};

#endif
