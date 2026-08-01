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

#ifndef ECHO_H
#define ECHO_H

#include <string>
#include <vector>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

class Echo
{
public:
    struct Address
    {
        Address();
        Address(const struct sockaddr *address, socklen_t length);
        static Address ipv4(uint32_t hostOrderAddress);
        int family() const;
        bool isIpv4() const;
        uint32_t ipv4Value() const;
        const struct sockaddr *sockaddrValue() const;
        socklen_t length() const { return addressLength; }
        std::string format() const;
        bool operator==(const Address &other) const;
        bool operator!=(const Address &other) const { return !(*this == other); }

        struct sockaddr_storage storage;
        socklen_t addressLength;
    };

    Echo(int maxPayloadSize, bool preferUnprivileged = false);
    ~Echo();

    int getFd() { return fd; }
    int getIpv6Fd() { return ipv6Fd; }

    void send(int payloadLength, const Address &address, bool reply,
              uint16_t id, uint16_t seq);
    int receive(int readyFd, Address &address, bool &reply,
                uint16_t &id, uint16_t &seq);

    char *sendPayloadBuffer();
    char *receivePayloadBuffer();

    static int headerSize();
protected:
    struct EchoHeader
    {
        uint8_t type;
        uint8_t code;
        uint16_t chksum;
        uint16_t id;
        uint16_t seq;
    }; // size = 8

    uint16_t icmpChecksum(const char *data, int length);

    int fd;
    int ipv6Fd;
    int bufferSize;
    bool datagramSocket;
    bool ipv6DatagramSocket;
#ifdef WIN32
    class WindowsBackend;
    WindowsBackend *windowsBackend;
#endif
    std::vector<char> sendBuffer;
    std::vector<char> receiveBuffer;
};

#endif
