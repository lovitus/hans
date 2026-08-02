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

#ifndef WORKER_H
#define WORKER_H

#include "time.h"
#include "echo.h"
#include "tun.h"
#include "transport.h"
#include "secure.h"

#include <string>
#include <sys/types.h>
#include <sys/select.h>

class Worker
{
public:
    Worker(int tunnelMtu, const std::string *deviceName, bool answerEcho,
           uid_t uid, gid_t gid, bool createTun = true,
           bool preferUnprivilegedEcho = false);
    virtual ~Worker() { }

    virtual void run();
    virtual void stop();

    static int headerSize()
    {
        return sizeof(TunnelHeader) + TransportV3::HEADER_SIZE +
               SecureTransport::OVERHEAD;
    }

protected:
    struct TunnelHeader
    {
        struct Magic
        {
            Magic() { }
            Magic(const char *magic);

            bool operator==(const Magic &other) const;
            bool operator!=(const Magic &other) const;

            char data[4];
        };

        enum Type
        {
            TYPE_RESET_CONNECTION = 1,
            TYPE_CONNECTION_REQUEST = 2,
            TYPE_CHALLENGE = 3,
            TYPE_CHALLENGE_RESPONSE = 4,
            TYPE_CONNECTION_ACCEPT = 5,
            TYPE_CHALLENGE_ERROR = 6,
            TYPE_DATA = 7,
            TYPE_POLL = 8,
            TYPE_SERVER_FULL = 9,
            TYPE_DIRECT_PROBE = 10,
            TYPE_DIRECT_PROBE_REPLY = 11,
            TYPE_MODE_SET = 12,
            TYPE_MODE_ACK = 13,
            TYPE_TRANSPORT_PING = 14,
            TYPE_HANDSHAKE_INIT = 15,
            TYPE_HANDSHAKE_RESPONSE = 16,
            TYPE_HANDSHAKE_FINISH = 17
        };

        Magic magic;
        uint8_t type;
    }; // size = 5

    virtual bool handleEchoData(const TunnelHeader &header, int dataLength,
                                const Echo::Address &realAddress, bool reply,
                                uint16_t id, uint16_t seq);
    virtual void handleTunData(int dataLength, uint32_t sourceIp,
                               uint32_t destIp); // to echoSendPayloadBuffer
    virtual void handleTimeout();
    virtual int addFileDescriptors(fd_set &readSet, fd_set &writeSet,
                                   int maxFd);
    virtual void handleFileDescriptors(fd_set &readSet, fd_set &writeSet);
    virtual int idleIntervalMilliseconds() const;
    virtual void handleIdle();

    void sendEcho(const TunnelHeader::Magic &magic, TunnelHeader::Type type,
                  int length, const Echo::Address &realAddress, bool reply,
                  uint16_t id, uint16_t seq);
    void sendToTun(int length); // from echoReceivePayloadBuffer

    void setTimeout(Time delta);

    char *echoSendPayloadBuffer();
    char *echoReceivePayloadBuffer();

    int payloadBufferSize()
    {
        return tunnelMtu + TransportV3::HEADER_SIZE + SecureTransport::OVERHEAD;
    }

    void dropPrivileges();

    Echo echo;
    Tun tun;
    bool alive;
    bool answerEcho;
    int tunnelMtu;
    int maxTunnelHeaderSize;
    uid_t uid;
    gid_t gid;

    bool privilegesDropped;

    Time now;
private:
    void handleEchoFd(int readyFd);
    int readIcmpData(int *realIp, int *id, int *seq);

    Time nextTimeout;
};

#endif
