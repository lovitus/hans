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

#ifndef CLIENT_H
#define CLIENT_H

#include "worker.h"
#include "auth.h"
#include "transport.h"
#include "userspace.h"
#include "secure.h"

#include <map>
#include <vector>

class Client : public Worker, public UserspaceNetworkObserver
{

public:
    Client(int tunnelMtu, const std::string *deviceName, uint32_t serverIp,
           int maxPolls, const std::string &passphrase, uid_t uid, gid_t gid,
           bool changeEchoId, bool changeEchoSeq, uint32_t desiredIp,
           const std::string &deviceId, bool userspace = false,
           const std::string &socksAddress = std::string(),
           const std::vector<SharePort> &sharePorts = std::vector<SharePort>(),
           const std::string &identityFile = std::string());
    virtual ~Client();

    virtual void run();

    static const Worker::TunnelHeader::Magic magic;
    static const Worker::TunnelHeader::Magic v2Magic;
    static const Worker::TunnelHeader::Magic v3Magic;
    static const Worker::TunnelHeader::Magic v4Magic;
protected:
    enum State
    {
        STATE_CLOSED,
        STATE_CONNECTION_REQUEST_SENT,
        STATE_CHALLENGE_RESPONSE_SENT,
        STATE_ESTABLISHED
    };

    virtual bool handleEchoData(const TunnelHeader &header, int dataLength, uint32_t realIp, bool reply, uint16_t id, uint16_t seq);
    virtual void handleTunData(int dataLength, uint32_t sourceIp, uint32_t destIp);
    virtual void handleTimeout();
    virtual int addFileDescriptors(fd_set &readSet, fd_set &writeSet,
                                   int maxFd);
    virtual void handleFileDescriptors(fd_set &readSet, fd_set &writeSet);
    virtual int idleIntervalMilliseconds() const;
    virtual void handleIdle();
    virtual void sendUserspacePacket(const char *packet, int length);

    void handleDataFromServer(int length);

    void startPolling();
    void fillPollWindow();
    void transportTick();
    void startDirectProbe();
    void requestMode(uint8_t mode);
    void switchToCredit(const char *reason);
    bool parseTransportHeader(int &dataLength, TransportV3::Header &transport,
                              uint16_t id, uint16_t seq);
    void sendV3ToServer(Worker::TunnelHeader::Type type, int dataLength,
                        uint8_t flags, bool trackPoll);
    bool openV4Packet(const TunnelHeader &header, int &dataLength);
    void sendV4HandshakeFinish();
    uint32_t echoKey(uint16_t id, uint16_t seq) const;
    const Worker::TunnelHeader::Magic &clientMagic() const;
    const Worker::TunnelHeader::Magic &serverMagic() const;

    void sendEchoToServer(Worker::TunnelHeader::Type type, int dataLength);
    void sendChallengeResponse(int dataLength);
    void sendConnectionRequest();

    Auth auth;

    uint32_t serverIp;
    uint32_t clientIp;
    uint32_t desiredIp;
    std::string deviceId;
    int protocolVersion;
    int protocolRequestAttempts;

    int maxPolls;
    int pollTimeoutNr;
    bool autoPoll;
    int negotiatedCapabilities;
    uint32_t sessionId;
    uint32_t localReceiverIndex;
    uint32_t peerReceiverIndex;
    SecureIdentity secureIdentity;
    uint8_t securePsk[32];
    NoiseHandshake *secureHandshake;
    SecureTransport secureTransport;
    uint32_t nextTransportSequence;
    SequenceTracker receivedSequences;
    AdaptiveCredit adaptiveCredit;
    std::map<uint32_t, Time> outstandingPolls;
    uint8_t transportMode;
    uint8_t peerTransportMode;
    bool directProbePending;
    int directProbeReplies;
    Time directProbeDeadline;
    Time lastDirectProbe;
    Time lastServerPacket;
    Time lastTransportPing;
    Time lastModeRequest;

    bool changeEchoId, changeEchoSeq;

    uint16_t nextEchoId;
    uint16_t nextEchoSequence;

    State state;
    UserspaceNetwork *userspaceNetwork;
};

#endif
