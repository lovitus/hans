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
#include "userspace.h"

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
#include <fstream>
#include <sys/stat.h>

#ifndef AI_V4MAPPED // Not supported on OpenBSD 6.0
#define AI_V4MAPPED 0
#endif

using std::string;
using std::vector;

static Worker *worker = NULL;

static string loadSecretFile(const string &path)
{
    struct stat info;
    if (stat(path.c_str(), &info) != 0)
        throw Exception("could not inspect secret file", true);
#ifndef WIN32
    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0)
        throw Exception("secret file must not be accessible by group or others");
#endif
    std::ifstream input(path.c_str(), std::ios::in | std::ios::binary);
    if (!input)
        throw Exception("could not open secret file", true);
    string secret((std::istreambuf_iterator<char>(input)),
                  std::istreambuf_iterator<char>());
    while (!secret.empty() &&
           (secret[secret.size() - 1] == '\n' ||
            secret[secret.size() - 1] == '\r'))
        secret.erase(secret.size() - 1);
    if (secret.empty() || secret.size() > 255)
        throw Exception("secret file must contain between 1 and 255 bytes");
    return secret;
}

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
        "Hans - IP over ICMP version 1.5\n\n"
        "RUN AS CLIENT (TUN/TAP, DEFAULT)\n"
        "  hans -c server [-fv] [-p passphrase] [-u user] [-d tun_device]\n"
        "       [-m reference_mtu] [-w auto|polls] [--device-id id]\n"
        "       [--device-id-file path]\n"
        "       [--identity-file path] [--server-fingerprint hex] [--require-v4]\n\n"
        "RUN AS USERSPACE CLIENT (NO TUN/TAP)\n"
        "  hans -c server [-fv] [-p passphrase] [-u user]\n"
        "       [-m reference_mtu] [-w auto|polls] [--device-id id]\n"
        "       [--device-id-file path] --feature userspace\n"
        "       [--socks5 IPv4:port] [--shareports mappings] [--allports]\n"
        "       [--socks5-user name] [--socks5-password-file path]\n"
        "       [--identity-file path] [--server-fingerprint hex] [--require-v4]\n\n"
        "RUN AS SERVER (linux only)\n"
        "  hans -s network [-fvr] [-p passphrase] [-u user] [-d tun_device]\n"
        "       [-m reference_mtu] [--lease-file path]\n\n"
        "LIST SERVER PEERS\n"
        "  hans --list-peers [--lease-file path]\n\n"
        "SHOW CLIENT DEVICE ID\n"
        "  hans --show-device-id [--device-id-file path]\n\n"
        "SHOW SECURE IDENTITY\n"
        "  hans --show-identity [--identity-file path]\n\n"
        "DIAGNOSTICS\n"
        "  hans --doctor [--json]\n\n"
        "ARGUMENTS\n"
        "  -c server     Run as client. Connect to given server address.\n"
        "  -s network    Run as server. Use given network address on virtual interfaces.\n"
        "  -p passphrase Set passphrase.\n"
        "  --passphrase-file path\n"
        "                Read the tunnel passphrase from a private file.\n"
        "  -u username   Change user under which the program runs.\n"
        "  -a ip         Request assignment of given tunnel ip address from the server.\n"
        "  -I id         Use an explicit persistent 32-hex-character device id.\n"
        "  -k path       Load/create the client device id in this file.\n"
        "  -j path       Store/read sticky server leases in this file.\n"
        "  -l            List peers from the server lease file and exit.\n"
        "  --json        Emit machine-readable JSON with --list-peers.\n"
        "  --doctor      Check secure randomness and ICMP transport access.\n"
        "  -o            Print the persistent client device id and exit.\n"
        "  -r            Respond to ordinary pings in server mode.\n"
        "  -d device     Use given tun device.\n"
        "  -m mtu        Set maximum echo packet size. This should correspond to the MTU\n"
        "                of the network between client and server, which is usually 1500\n"
        "                over Ethernet. Has to be the same on client and server. Defaults\n"
        "                to 1500.\n"
        "  -w auto|polls Adaptive echo-request credits and direct-reply probing are used\n"
        "                by default. A number forces a fixed legacy window; 0 forces\n"
        "                direct replies without automatic fallback.\n"
        "  -i            Change echo id on every echo request. May help with buggy\n"
        "                routers. May impact performance with others.\n"
        "  -q            Change echo sequence number on every echo request. May help with\n"
        "                buggy routers. May impact performance with others.\n"
        "\nUSERSPACE CLIENT OPTIONS (require --feature userspace)\n"
        "  --feature userspace\n"
        "                Run the client without TUN/TAP and use the embedded TCP/IP stack.\n"
        "  --socks5 ip:port\n"
        "                Expose a local SOCKS5 CONNECT/UDP gateway to VPN peers.\n"
        "                This is not a SOCKS service for normal TUN/TAP mode.\n"
        "  --socks5-user name\n"
        "                Require RFC 1929 username/password authentication.\n"
        "  --socks5-password-file path\n"
        "                Read the SOCKS5 password from a private file.\n"
        "  --shareports mappings\n"
        "                Share VPN ports. A plain port maps to 127.0.0.1:same-port;\n"
        "                use listen-port=target-ip:target-port to override it.\n"
        "  --allports    Share every otherwise-unmapped TCP port to\n"
        "                127.0.0.1:same-port. Explicit --shareports win.\n"
        "\nSECURE TRANSPORT OPTIONS\n"
        "  --identity-file path\n"
        "                Load/create the Noise static key at this path.\n"
        "  --show-identity\n"
        "                Print the stable fingerprint derived from that key.\n"
        "  --server-fingerprint hex\n"
        "                Require the server Noise key to match this fingerprint.\n"
        "  --require-v4  Refuse unauthenticated downgrade to legacy protocols.\n"
        "  -h, --help    Show this help and exit.\n"
        "  -f            Run in foreground.\n"
        "  -v            Print debug information.\n";
}

int main(int argc, char *argv[])
{
    string serverName;
    string userName;
    string passphrase;
    string passphraseFile;
    bool passphraseSpecified = false;
    string device;
    bool isServer = false;
    bool isClient = false;
    bool foreground = false;
    int mtu = 1500;
    int maxPolls = -1;
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
    bool userspace = false;
    string socksAddress;
    vector<SharePort> sharePorts;
    bool allPorts = false;
    string identityFile;
    string serverFingerprint;
    bool showIdentity = false;
    bool requireV4 = false;
    bool json = false;
    bool doctor = false;
    string socksUser;
    string socksPasswordFile;
    string socksPassword;

    openlog(argv[0], LOG_PERROR, LOG_DAEMON);

    enum { OPTION_FEATURE = 1000, OPTION_SOCKS5, OPTION_SHAREPORTS,
           OPTION_ALLPORTS,
           OPTION_IDENTITY_FILE, OPTION_SHOW_IDENTITY,
           OPTION_SERVER_FINGERPRINT, OPTION_REQUIRE_V4,
           OPTION_SOCKS5_USER, OPTION_SOCKS5_PASSWORD_FILE, OPTION_JSON,
           OPTION_DOCTOR, OPTION_PASSPHRASE_FILE };
    static struct option longOptions[] = {
        {"help", no_argument, NULL, 'h'},
        {"device-id", required_argument, NULL, 'I'},
        {"device-id-file", required_argument, NULL, 'k'},
        {"lease-file", required_argument, NULL, 'j'},
        {"list-peers", no_argument, NULL, 'l'},
        {"show-device-id", no_argument, NULL, 'o'},
        {"feature", required_argument, NULL, OPTION_FEATURE},
        {"socks5", required_argument, NULL, OPTION_SOCKS5},
        {"shareports", required_argument, NULL, OPTION_SHAREPORTS},
        {"allports", no_argument, NULL, OPTION_ALLPORTS},
        {"identity-file", required_argument, NULL, OPTION_IDENTITY_FILE},
        {"show-identity", no_argument, NULL, OPTION_SHOW_IDENTITY},
        {"server-fingerprint", required_argument, NULL, OPTION_SERVER_FINGERPRINT},
        {"require-v4", no_argument, NULL, OPTION_REQUIRE_V4},
        {"socks5-user", required_argument, NULL, OPTION_SOCKS5_USER},
        {"socks5-password-file", required_argument, NULL, OPTION_SOCKS5_PASSWORD_FILE},
        {"json", no_argument, NULL, OPTION_JSON},
        {"doctor", no_argument, NULL, OPTION_DOCTOR},
        {"passphrase-file", required_argument, NULL, OPTION_PASSPHRASE_FILE},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "hfru:d:p:s:c:m:w:qiva:I:k:j:lo",
                            longOptions, NULL)) != -1)
    {
        switch(c) {
            case 'h':
                usage();
                return 0;
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
                passphraseSpecified = true;
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
                if (strcmp(optarg, "auto") == 0)
                    maxPolls = -1;
                else
                {
                    char *end = NULL;
                    long parsed = strtol(optarg, &end, 10);
                    if (end == optarg || *end != '\0' || parsed < 0 ||
                        parsed > 255)
                    {
                        std::cerr << "invalid poll window\n";
                        return 1;
                    }
                    maxPolls = (int)parsed;
                }
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
            case OPTION_FEATURE:
                if (strcmp(optarg, "userspace") != 0)
                {
                    std::cerr << "unknown feature: " << optarg << "\n";
                    return 1;
                }
                userspace = true;
                break;
            case OPTION_SOCKS5:
                socksAddress = optarg;
                break;
            case OPTION_SHAREPORTS:
            {
                string error;
                if (!UserspaceNetwork::parseSharePorts(optarg, sharePorts, error))
                {
                    std::cerr << "invalid --shareports: " << error << "\n";
                    return 1;
                }
                break;
            }
            case OPTION_ALLPORTS:
                allPorts = true;
                break;
            case OPTION_IDENTITY_FILE:
                identityFile = optarg;
                break;
            case OPTION_SHOW_IDENTITY:
                showIdentity = true;
                break;
            case OPTION_SERVER_FINGERPRINT:
                try { serverFingerprint = Utility::normalizeDeviceId(optarg); }
                catch (Exception e)
                {
                    std::cerr << "invalid --server-fingerprint: "
                              << e.errorMessage() << "\n";
                    return 1;
                }
                break;
            case OPTION_REQUIRE_V4:
                requireV4 = true;
                break;
            case OPTION_SOCKS5_USER:
                socksUser = optarg;
                break;
            case OPTION_SOCKS5_PASSWORD_FILE:
                socksPasswordFile = optarg;
                break;
            case OPTION_JSON:
                json = true;
                break;
            case OPTION_DOCTOR:
                doctor = true;
                break;
            case OPTION_PASSPHRASE_FILE:
                passphraseFile = optarg;
                break;
            default:
                usage();
                return 1;
        }
    }

    if (listPeers)
        return Server::listPeers(leaseFile, json);

    if (doctor)
    {
        bool randomOk = false;
        bool icmpOk = false;
        string error;
        try
        {
            uint8_t sample[32];
            Utility::secureRandom(sample, sizeof(sample));
            randomOk = true;
            Echo probe(64, true);
            icmpOk = probe.getFd() >= 0;
            memset(sample, 0, sizeof(sample));
        }
        catch (Exception e)
        {
            error = e.errorMessage();
        }
        if (json)
            std::cout << "{\"secure_random\":" << (randomOk ? "true" : "false")
                      << ",\"icmp_transport\":" << (icmpOk ? "true" : "false")
                      << ",\"ready\":" << (randomOk && icmpOk ? "true" : "false")
                      << "}" << std::endl;
        else
        {
            std::cout << "secure random: " << (randomOk ? "ok" : "failed") << '\n'
                      << "ICMP transport: " << (icmpOk ? "ok" : "failed") << '\n';
            if (!error.empty())
                std::cout << "error: " << error << '\n';
        }
        return randomOk && icmpOk ? 0 : 1;
    }

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

    if (showIdentity)
    {
        try
        {
            SecureIdentity identity;
            identity.loadOrCreate(identityFile.empty() ?
                                  Utility::defaultStateFile("identity.key") :
                                  identityFile);
            std::cout << identity.fingerprint() << std::endl;
            return 0;
        }
        catch (Exception e)
        {
            syslog(LOG_ERR, "%s", e.errorMessage().data());
            return 1;
        }
    }

    if (!passphraseFile.empty())
    {
        if (passphraseSpecified)
        {
            std::cerr << "-p and --passphrase-file cannot be used together\n";
            return 1;
        }
        try { passphrase = loadSecretFile(passphraseFile); }
        catch (Exception e)
        {
            syslog(LOG_ERR, "%s", e.errorMessage().data());
            return 1;
        }
    }

    if (!socksUser.empty() || !socksPasswordFile.empty())
    {
        if (socksUser.empty() || socksUser.size() > 255 ||
            socksPasswordFile.empty())
        {
            std::cerr << "--socks5-user and --socks5-password-file must be used together\n";
            return 1;
        }
        try { socksPassword = loadSecretFile(socksPasswordFile); }
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
        (maxPolls < -1 || maxPolls > 255) ||
        (isServer && (changeEchoSeq || changeEchoId)) ||
        (userspace && (!isClient ||
                       (socksAddress.empty() && sharePorts.empty() && !allPorts))) ||
        (!userspace && (!socksAddress.empty() || !sharePorts.empty() || allPorts)) ||
        (userspace && !device.empty()) ||
        ((!socksUser.empty() || !socksPasswordFile.empty()) &&
         (!userspace || socksAddress.empty())) ||
        (isServer && (!serverFingerprint.empty() || requireV4)))
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
                                network, answerPing, uid, gid, 5000, leaseFile,
                                identityFile);
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
            struct addrinfo *ipv6Address = NULL;

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
                else if (candidate->ai_family == AF_INET6 && ipv6Address == NULL)
                    ipv6Address = candidate;
            }

            if (address == NULL)
            {
                address = ipv6Address;
                if (address == NULL)
                {
                    syslog(LOG_ERR, "server name has no usable IPv4 or IPv6 address");
                    freeaddrinfo(res);
                    return 1;
                }
            }

            Echo::Address serverAddress(address->ai_addr,
                                        (socklen_t)address->ai_addrlen);

            worker = new Client(mtu, device.empty() ? NULL : &device,
                                serverAddress, maxPolls, passphrase, uid, gid,
                                changeEchoId, changeEchoSeq, clientIp, deviceId,
                                userspace, socksAddress, sharePorts, allPorts,
                                identityFile,
                                requireV4, serverFingerprint, socksUser,
                                socksPassword);

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
