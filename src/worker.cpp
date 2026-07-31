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

#include "worker.h"
#include "tun.h"
#include "exception.h"
#include "config.h"

#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/select.h>
#include <grp.h>
#include <iostream>

using std::cout;
using std::endl;

Worker::TunnelHeader::Magic::Magic(const char *magic)
{
    memset(data, 0, sizeof(data));
    strncpy(data, magic, sizeof(data));
}

bool Worker::TunnelHeader::Magic::operator==(const Magic &other) const
{
    return memcmp(data, other.data, sizeof(data)) == 0;
}

bool Worker::TunnelHeader::Magic::operator!=(const Magic &other) const
{
    return memcmp(data, other.data, sizeof(data)) != 0;
}

Worker::Worker(int tunnelMtu, const std::string *deviceName, bool answerEcho,
               uid_t uid, gid_t gid, bool createTun,
               bool preferUnprivilegedEcho)
    : echo(tunnelMtu + sizeof(TunnelHeader) + TransportV3::HEADER_SIZE,
           preferUnprivilegedEcho),
      tun(deviceName, tunnelMtu, createTun)
{
    this->tunnelMtu = tunnelMtu;
    this->answerEcho = answerEcho;
    this->uid = uid;
    this->gid = gid;
    this->privilegesDropped = false;
}

void Worker::sendEcho(const TunnelHeader::Magic &magic, TunnelHeader::Type type,
                      int length, uint32_t realIp, bool reply, uint16_t id, uint16_t seq)
{
    if (length > payloadBufferSize())
        throw Exception("packet too big");

    TunnelHeader *header = (TunnelHeader *)echo.sendPayloadBuffer();
    header->magic = magic;
    header->type = type;

    DEBUG_ONLY(
        cout << "sending: type " << type << ", length " << length
             << ", id " << id << ", seq " << seq << endl);

    echo.send(length + sizeof(TunnelHeader), realIp, reply, id, seq);
}

void Worker::sendToTun(int length)
{
    tun.write(echoReceivePayloadBuffer(), length);
}

void Worker::setTimeout(Time delta)
{
    nextTimeout = now + delta;
}

void Worker::run()
{
    now = Time::now();
    alive = true;

    while (alive)
    {
        fd_set readSet;
        fd_set writeSet;
        Time timeout;

        FD_ZERO(&readSet);
        FD_ZERO(&writeSet);
        int maxFd = echo.getFd();
        FD_SET(echo.getFd(), &readSet);
        if (tun.getFd() >= 0)
        {
            FD_SET(tun.getFd(), &readSet);
            if (tun.getFd() > maxFd)
                maxFd = tun.getFd();
        }
        maxFd = addFileDescriptors(readSet, writeSet, maxFd);

        Time wakeAt = nextTimeout;
        int idleMs = idleIntervalMilliseconds();
        if (idleMs >= 0)
        {
            Time idleAt = now + Time(idleMs);
            if (wakeAt == Time::ZERO || idleAt < wakeAt)
                wakeAt = idleAt;
        }
        if (wakeAt != Time::ZERO)
        {
            timeout = wakeAt - now;
            if (timeout < Time::ZERO)
                timeout = Time::ZERO;
        }

        // wait for data or timeout
        timeval *timeval = wakeAt != Time::ZERO ? &timeout.getTimeval() : NULL;
        int result = select(maxFd + 1, &readSet, &writeSet, NULL, timeval);
        if (result == -1)
        {
            if (alive)
                throw Exception("select", true);
            else
                return;
        }
        now = Time::now();

        // icmp data
        if (FD_ISSET(echo.getFd(), &readSet))
        {
            bool reply;
            uint16_t id, seq;
            uint32_t ip;

            int dataLength = echo.receive(ip, reply, id, seq);
            if (dataLength != -1)
            {
                bool valid = dataLength >= sizeof(TunnelHeader);

                if (valid)
                {
                    TunnelHeader *header = (TunnelHeader *)echo.receivePayloadBuffer();

                    DEBUG_ONLY(
                        cout << "received: type " << header->type
                             << ", length " << dataLength - sizeof(TunnelHeader)
                             << ", id " << id << ", seq " << seq << endl);

                    valid = handleEchoData(*header, dataLength - sizeof(TunnelHeader), ip, reply, id, seq);
                }

                if (!valid && !reply && answerEcho)
                {
                    memcpy(echo.sendPayloadBuffer(), echo.receivePayloadBuffer(), dataLength);
                    echo.send(dataLength, ip, true, id, seq);
                }
            }
        }

        // data from tun
        if (tun.getFd() >= 0 && FD_ISSET(tun.getFd(), &readSet))
        {
            uint32_t sourceIp, destIp;

            int dataLength = tun.read(echoSendPayloadBuffer(), sourceIp, destIp);

            if (dataLength == 0)
                throw Exception("tunnel closed");

            if (dataLength != -1)
                handleTunData(dataLength, sourceIp, destIp);
        }

        handleFileDescriptors(readSet, writeSet);
        handleIdle();

        if (nextTimeout != Time::ZERO &&
            (now > nextTimeout || now == nextTimeout))
        {
            nextTimeout = Time::ZERO;
            handleTimeout();
        }
    }
}

void Worker::stop()
{
    alive = false;
}

void Worker::dropPrivileges()
{
    if (uid <= 0 || privilegesDropped)
        return;

#ifdef WIN32
    throw Exception("dropping privileges not supported");
#else
    syslog(LOG_INFO, "dropping privileges");

    if (setgroups(0, NULL) == -1)
        throw Exception("setgroups", true);

    if (setgid(gid) == -1)
        throw Exception("setgid", true);

    if (setuid(uid) == -1)
        throw Exception("setuid", true);

    privilegesDropped = true;
#endif
}

bool Worker::handleEchoData(const TunnelHeader &, int, uint32_t, bool, uint16_t, uint16_t)
{
    return true;
}

void Worker::handleTunData(int, uint32_t, uint32_t) { }

void Worker::handleTimeout() { }

int Worker::addFileDescriptors(fd_set &, fd_set &, int maxFd)
{
    return maxFd;
}

void Worker::handleFileDescriptors(fd_set &, fd_set &) { }

int Worker::idleIntervalMilliseconds() const
{
    return -1;
}

void Worker::handleIdle() { }

char *Worker::echoSendPayloadBuffer()
{
    return echo.sendPayloadBuffer() + sizeof(TunnelHeader);
}

char *Worker::echoReceivePayloadBuffer()
{
    return echo.receivePayloadBuffer() + sizeof(TunnelHeader);
}
