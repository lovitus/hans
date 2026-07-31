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
#include "utility.h"

#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pwd.h>
#include <netdb.h>
// #include <uuid/uuid.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include <memory>
#include <getopt.h>

#ifndef AI_V4MAPPED // Not supported on OpenBSD 6.0
#define AI_V4MAPPED 0
#endif

using std::string;

static Worker *worker = NULL;

static void sig_term_handler(int)
{
    syslog(LOG_INFO, "SIGTERM received");
    if (worker)
        worker->stop();
}

static void sig_int_handler(int)
{
    syslog(LOG_INFO, "SIGINT received");
    if (worker)
        worker->stop();
}

static void usage()
{
    std::cerr <<
        "Hans - IP over ICMP version 1.2\n\n"
        "RUN AS CLIENT\n"
        "  hans -c server [-fv] [-p passphrase] [-u user] [-d tun_device]\n"
        "       [-m reference_mtu] [-w polls] [--device-id id]\n"
        "       [--device-id-file path]\n\n"
        "RUN AS SERVER (linux only)\n"
        "  hans -s network [-fvr] [-p passphrase] [-u user] [-d tun_device]\n"
        "       [-m reference_mtu] [--lease-file path]\n\n"
        "LIST SERVER PEERS\n"
        "  hans --list-peers [--lease-file path]\n\n"
        "SHOW CLIENT DEVICE ID\n"
        "  hans --show-device-id [--device-id-file path]\n\n"
        "ARGUMENTS\n"
        "  -c server     Run as client. Connect to given server address.\n"
        "  -s network    Run as server. Use given network address on virtual interfaces.\n"
        "  -p passphrase Set passphrase.\n"
        "  -u username   Change user under which the program runs.\n"
        "  -a ip         Request assignment of given tunnel ip address from the server.\n"
        "  -I id         Use an explicit persistent 32-hex-character device id.\n"
        "  -k path       Load/create the client device id in this file.\n"
        "  -j path       Store/read sticky server leases in this file.\n"
        "  -l            List peers from the server lease file and exit.\n"
        "  -o            Print the persistent client device id and exit.\n"
        "  -r            Respond to ordinary pings in server mode.\n"
        "  -d device     Use given tun device.\n"
        "  -m mtu        Set maximum echo packet size. This should correspond to the MTU\n"
        "                of the network between client and server, which is usually 1500\n"
        "                over Ethernet. Has to be the same on client and server. Defaults\n"
        "                to 1500.\n"
        "  -w polls      Number of echo requests the client sends in advance for the\n"
        "                server to reply to. 0 disables polling, which is the best choice\n"
        "                if the network allows unlimited echo replies. Defaults to 10.\n"
        "  -i            Change echo id on every echo request. May help with buggy\n"
        "                routers. May impact performance with others.\n"
        "  -q            Change echo sequence number on every echo request. May help with\n"
        "                buggy routers. May impact performance with others.\n"
        "  -f            Run in foreground.\n"
        "  -v            Print debug information.\n";
}

int main(int argc, char *argv[])
{
    string serverName;
    string userName;
    string passphrase;
    string device;
    bool isServer = false;
    bool isClient = false;
    bool foreground = false;
    int mtu = 1500;
    int maxPolls = 10;
    uint32_t network = INADDR_NONE;
    uint32_t clientIp = INADDR_NONE;
    bool answerPing = false;
    uid_t uid = 0;
    gid_t gid = 0;
    bool changeEchoId = false;
    bool changeEchoSeq = false;
    bool verbose = false;
    string deviceId;
    string deviceIdFile;
    string leaseFile = Utility::defaultStateFile("leases");
    bool listPeers = false;
    bool showDeviceId = false;

    openlog(argv[0], LOG_PERROR, LOG_DAEMON);

    static struct option longOptions[] = {
        {"device-id", required_argument, NULL, 'I'},
        {"device-id-file", required_argument, NULL, 'k'},
        {"lease-file", required_argument, NULL, 'j'},
        {"list-peers", no_argument, NULL, 'l'},
        {"show-device-id", no_argument, NULL, 'o'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "fru:d:p:s:c:m:w:qiva:I:k:j:lo",
                            longOptions, NULL)) != -1)
    {
        switch(c) {
            case 'f':
                foreground = true;
                break;
            case 'u':
                userName = optarg;
                break;
            case 'd':
                device = optarg;
                break;
            case 'p':
                passphrase = optarg;
                memset(optarg, 0, strlen(optarg));
                break;
            case 'c':
                isClient = true;
                serverName = optarg;
                break;
            case 's':
                isServer = true;
                network = ntohl(inet_addr(optarg));
                if (network == INADDR_NONE)
                    std::cerr << "invalid network\n";
                break;
            case 'm':
                mtu = atoi(optarg);
                break;
            case 'w':
                maxPolls = atoi(optarg);
                break;
            case 'r':
                answerPing = true;
                break;
            case 'q':
                changeEchoSeq = true;
                break;
            case 'i':
                changeEchoId = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'a':
                clientIp = ntohl(inet_addr(optarg));
                break;
            case 'I':
                deviceId = optarg;
                break;
            case 'k':
                deviceIdFile = optarg;
                break;
            case 'j':
                leaseFile = optarg;
                break;
            case 'l':
                listPeers = true;
                break;
            case 'o':
                showDeviceId = true;
                break;
            default:
                usage();
                return 1;
        }
    }

    if (listPeers)
        return Server::listPeers(leaseFile);

    if (showDeviceId)
    {
        try
        {
            if (!deviceId.empty() && !deviceIdFile.empty())
                throw Exception("--device-id and --device-id-file cannot be used together");
            if (!deviceId.empty())
                deviceId = Utility::normalizeDeviceId(deviceId);
            else
            {
                if (deviceIdFile.empty())
                    deviceIdFile = Utility::defaultStateFile("device-id");
                deviceId = Utility::loadOrCreateDeviceId(deviceIdFile);
            }
            std::cout << deviceId << std::endl;
            return 0;
        }
        catch (Exception e)
        {
            syslog(LOG_ERR, "%s", e.errorMessage().data());
            return 1;
        }
    }

    mtu -= Echo::headerSize() + Worker::headerSize();

    if (mtu < 68)
    {
        // RFC 791: Every internet module must be able to forward a datagram of
        // 68 octets without further fragmentation.
        std::cerr << "mtu too small\n";
        return 1;
    }

    if ((isClient == isServer) ||
        (isServer && network == INADDR_NONE) ||
        (maxPolls < 0 || maxPolls > 255) ||
        (isServer && (changeEchoSeq || changeEchoId)))
    {
        usage();
        return 1;
    }

    if (!userName.empty())
    {
#ifdef WIN32
        syslog(LOG_ERR, "dropping privileges is not supported on Windows");
        return 1;
#endif
        passwd *pw = getpwnam(userName.data());

        if (pw != NULL)
        {
            uid = pw->pw_uid;
            gid = pw->pw_gid;
        }
        else
        {
            syslog(LOG_ERR, "user not found");
            return 1;
        }
    }

    if (!verbose)
        setlogmask(LOG_UPTO(LOG_INFO));

    signal(SIGTERM, sig_term_handler);
    signal(SIGINT, sig_int_handler);

    try
    {
        if (isServer)
        {
            worker = new Server(mtu, device.empty() ? NULL : &device, passphrase,
                                network, answerPing, uid, gid, 5000, leaseFile);
        }
        else
        {
            if (!deviceId.empty() && !deviceIdFile.empty())
                throw Exception("--device-id and --device-id-file cannot be used together");

            if (deviceId.empty())
            {
                if (deviceIdFile.empty())
                    deviceIdFile = Utility::defaultStateFile("device-id");
                deviceId = Utility::loadOrCreateDeviceId(deviceIdFile);
            }
            else
            {
                deviceId = Utility::normalizeDeviceId(deviceId);
            }

            struct addrinfo hints = {0};
            struct addrinfo *res = NULL;
            struct addrinfo *address = NULL;
            bool foundIpv6 = false;

            hints.ai_family = AF_UNSPEC;
            hints.ai_flags = 0;

            int err = getaddrinfo(serverName.data(), NULL, &hints, &res);
            if (err)
            {
                syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(err));
                return 1;
            }

            for (struct addrinfo *candidate = res; candidate != NULL;
                 candidate = candidate->ai_next)
            {
                if (candidate->ai_family == AF_INET && address == NULL)
                    address = candidate;
                else if (candidate->ai_family == AF_INET6)
                    foundIpv6 = true;
            }

            if (address == NULL)
            {
                if (foundIpv6)
                    syslog(LOG_ERR, "server name resolves only to IPv6; Hans currently requires an IPv4 A record for its ICMP transport");
                else
                    syslog(LOG_ERR, "server name has no usable IPv4 address");
                freeaddrinfo(res);
                return 1;
            }

            sockaddr_in *sockaddr = reinterpret_cast<sockaddr_in *>(address->ai_addr);
            uint32_t serverIp = sockaddr->sin_addr.s_addr;

            worker = new Client(mtu, device.empty() ? NULL : &device,
                                ntohl(serverIp), maxPolls, passphrase, uid, gid,
                                changeEchoId, changeEchoSeq, clientIp, deviceId);

            freeaddrinfo(res);
        }

        if (!foreground)
        {
            syslog(LOG_INFO, "detaching from terminal");
            daemon(0, 0);
        }

        worker->run();
        delete worker;
        worker = NULL;
    }
    catch (Exception e)
    {
        syslog(LOG_ERR, "%s", e.errorMessage().data());
        delete worker;
        return 1;
    }

    return 0;
}
