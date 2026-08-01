#ifdef __CYGWIN__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#endif

#include "userspace.h"
#include "exception.h"
#include "time.h"
#include "utility.h"

extern "C" {
#include "lwip/init.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"
}

#include <algorithm>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <set>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

using std::string;
using std::vector;

extern "C" uint32_t hans_lwip_rand(void)
{
    return Utility::random32();
}

extern "C" u32_t sys_now(void)
{
    return (u32_t)(Time::now().milliseconds() & 0xffffffffu);
}

namespace
{
    const size_t MAX_BRIDGE_BUFFER = 1024 * 1024;

    bool parsePort(const string &text, uint16_t &port)
    {
        if (text.empty())
            return false;
        char *end = NULL;
        long value = strtol(text.c_str(), &end, 10);
        if (end == text.c_str() || *end != '\0' || value < 1 || value > 65535)
            return false;
        port = (uint16_t)value;
        return true;
    }

    bool setNonblocking(int fd)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        return flags != -1 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
    }

    void prepareSocket(int fd)
    {
#ifdef SO_NOSIGPIPE
        int enabled = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#else
        (void)fd;
#endif
    }

    void appendBytes(vector<char> &target, const void *data, size_t length)
    {
        const char *bytes = static_cast<const char *>(data);
        target.insert(target.end(), bytes, bytes + length);
    }

    void consumeBytes(vector<char> &buffer, size_t &offset, size_t count)
    {
        offset += count;
        if (offset == buffer.size())
        {
            buffer.clear();
            offset = 0;
        }
        else if (offset > 65536 && offset * 2 > buffer.size())
        {
            buffer.erase(buffer.begin(), buffer.begin() + offset);
            offset = 0;
        }
    }
}

class UserspaceNetwork::Impl
{
public:
    enum ConnectionKind
    {
        CONNECTION_SOCKS,
        CONNECTION_SHARE
    };

    enum SocksState
    {
        SOCKS_GREETING,
        SOCKS_AUTH,
        SOCKS_REQUEST,
        SOCKS_CONNECTING,
        SOCKS_STREAM,
        SOCKS_UDP
    };

    struct Connection
    {
        Connection(Impl *owner, ConnectionKind kind)
            : owner(owner), kind(kind), fd(-1), udpFd(-1), pcb(NULL), udpPcb(NULL),
              socksState(SOCKS_GREETING),
              hostConnecting(false), hostConnected(false), hostReadClosed(false),
              lwipReadClosed(false), lwipWriteClosed(false), closeAfterWrite(false),
              udpClientKnown(false), controlOffset(0), networkOffset(0),
              upstreamOffset(0)
        { memset(&udpClient, 0, sizeof(udpClient)); }

        Impl *owner;
        ConnectionKind kind;
        int fd;
        int udpFd;
        struct tcp_pcb *pcb;
        struct udp_pcb *udpPcb;
        SocksState socksState;
        bool hostConnecting;
        bool hostConnected;
        bool hostReadClosed;
        bool lwipReadClosed;
        bool lwipWriteClosed;
        bool closeAfterWrite;
        bool udpClientKnown;
        sockaddr_in udpClient;
        vector<char> controlIn;
        vector<char> controlOut;
        vector<char> networkOut;
        vector<char> upstream;
        size_t controlOffset;
        size_t networkOffset;
        size_t upstreamOffset;
    };

    struct SharedListener
    {
        Impl *owner;
        SharePort mapping;
        struct tcp_pcb *pcb;
    };

    Impl(UserspaceNetworkObserver *observer, int mtu,
         const string &socksAddress, const vector<SharePort> &sharePorts,
         const string &socksUser, const string &socksPassword)
        : observer(observer), mtu(mtu), socksAddress(socksAddress),
          sharePorts(sharePorts), socksUser(socksUser),
          socksPassword(socksPassword), socksFd(-1), configured(false)
    {
        memset(&interface, 0, sizeof(interface));
        lwip_init();
        if (!socksAddress.empty())
            openSocksListener();
    }

    ~Impl()
    {
        for (size_t i = 0; i < connections.size(); ++i)
            destroyConnection(connections[i], true);
        for (size_t i = 0; i < sharedListeners.size(); ++i)
        {
            if (sharedListeners[i]->pcb != NULL)
                tcp_close(sharedListeners[i]->pcb);
            delete sharedListeners[i];
        }
        if (socksFd >= 0)
            close(socksFd);
        if (configured)
            netif_remove(&interface);
    }

    static err_t netifInit(struct netif *netif)
    {
        netif->name[0] = 'h';
        netif->name[1] = 'u';
        netif->output = outputPacket;
        netif->mtu = static_cast<u16_t>(static_cast<Impl *>(netif->state)->mtu);
        netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
        return ERR_OK;
    }

    static err_t outputPacket(struct netif *netif, struct pbuf *p,
                              const ip4_addr_t *)
    {
        Impl *self = static_cast<Impl *>(netif->state);
        vector<char> packet(p->tot_len);
        pbuf_copy_partial(p, &packet[0], p->tot_len, 0);
        self->observer->sendUserspacePacket(&packet[0], (int)packet.size());
        return ERR_OK;
    }

    void configure(uint32_t ip, uint32_t gateway)
    {
        if (configured)
            return;
        ip4_addr_t address;
        ip4_addr_t netmask;
        ip4_addr_t gatewayAddress;
        ip4_addr_set_u32(&address, htonl(ip));
        ip4_addr_set_u32(&netmask, htonl(0xffffff00u));
        ip4_addr_set_u32(&gatewayAddress, htonl(gateway));
        if (netif_add(&interface, &address, &netmask, &gatewayAddress, this,
                      netifInit, ip4_input) == NULL)
            throw Exception("could not initialize userspace network stack");
        netif_set_default(&interface);
        netif_set_up(&interface);
        netif_set_link_up(&interface);
        configured = true;

        for (size_t i = 0; i < sharePorts.size(); ++i)
            openSharedListener(sharePorts[i]);
        syslog(LOG_INFO, "userspace network ready at %s", Utility::formatIp(ip).c_str());
    }

    void setMtu(int newMtu)
    {
        mtu = newMtu;
        if (configured)
            interface.mtu = (u16_t)newMtu;
    }

    void ingest(const char *packet, int length)
    {
        if (!configured || length <= 0)
            return;
        struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)length, PBUF_POOL);
        if (p == NULL || pbuf_take(p, packet, (u16_t)length) != ERR_OK)
        {
            if (p != NULL)
                pbuf_free(p);
            syslog(LOG_WARNING, "userspace packet dropped: lwIP input buffer exhausted");
            return;
        }
        if (interface.input(p, &interface) != ERR_OK)
            pbuf_free(p);
    }

    void openSocksListener()
    {
        uint32_t ip;
        uint16_t port;
        string error;
        if (!UserspaceNetwork::parseEndpoint(socksAddress, ip, port, error))
            throw Exception(string("invalid --socks5 address: ") + error);

        socksFd = socket(AF_INET, SOCK_STREAM, 0);
        socksBindIp = ip;
        if (socksFd < 0)
            throw Exception("creating SOCKS5 listener", true);
        prepareSocket(socksFd);
        int reuse = 1;
        setsockopt(socksFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (!setNonblocking(socksFd))
            throw Exception("setting SOCKS5 listener nonblocking", true);

        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(ip);
        address.sin_port = htons(port);
        if (bind(socksFd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
            listen(socksFd, 64) != 0)
            throw Exception("binding SOCKS5 listener", true);

        if ((ip & 0xff000000u) != 0x7f000000u && socksUser.empty())
            syslog(LOG_WARNING, "SOCKS5 is listening on a non-loopback address without authentication");
        syslog(LOG_INFO, "SOCKS5 listening on %s", socksAddress.c_str());
    }

    void openSharedListener(const SharePort &mapping)
    {
        SharedListener *listener = new SharedListener;
        listener->owner = this;
        listener->mapping = mapping;
        listener->pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
        if (listener->pcb == NULL)
        {
            delete listener;
            throw Exception("could not allocate shared-port listener");
        }
        ip_addr_t bindAddress;
        ip_addr_copy_from_ip4(bindAddress, *netif_ip4_addr(&interface));
        if (tcp_bind(listener->pcb, &bindAddress, mapping.listenPort) != ERR_OK)
        {
            tcp_abort(listener->pcb);
            delete listener;
            throw Exception("could not bind userspace shared port");
        }
        struct tcp_pcb *listening = tcp_listen_with_backlog(listener->pcb, 64);
        if (listening == NULL)
        {
            tcp_abort(listener->pcb);
            delete listener;
            throw Exception("could not listen on userspace shared port");
        }
        listener->pcb = listening;
        tcp_arg(listening, listener);
        tcp_accept(listening, acceptShared);
        sharedListeners.push_back(listener);
        syslog(LOG_INFO, "sharing VPN port %u to %s:%u",
               (unsigned)mapping.listenPort, Utility::formatIp(mapping.targetIp).c_str(),
               (unsigned)mapping.targetPort);
    }

    static err_t acceptShared(void *arg, struct tcp_pcb *newPcb, err_t error)
    {
        SharedListener *listener = static_cast<SharedListener *>(arg);
        if (error != ERR_OK)
            return error;
        Connection *connection = new Connection(listener->owner, CONNECTION_SHARE);
        connection->pcb = newPcb;
        tcp_backlog_accepted(newPcb);
        listener->owner->attachTcp(connection);
        if (!listener->owner->connectHost(connection, listener->mapping.targetIp,
                                           listener->mapping.targetPort))
        {
            listener->owner->abortTcp(connection);
            delete connection;
            return ERR_ABRT;
        }
        listener->owner->connections.push_back(connection);
        return ERR_OK;
    }

    bool connectHost(Connection *connection, uint32_t ip, uint16_t port)
    {
        connection->fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connection->fd < 0)
            return false;
        prepareSocket(connection->fd);
        if (!setNonblocking(connection->fd))
        {
            close(connection->fd);
            connection->fd = -1;
            return false;
        }
        sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = htonl(ip);
        target.sin_port = htons(port);
        int result = connect(connection->fd, reinterpret_cast<sockaddr *>(&target),
                             sizeof(target));
        if (result == 0)
        {
            connection->hostConnected = true;
            return true;
        }
        if (errno == EINPROGRESS || errno == EWOULDBLOCK)
        {
            connection->hostConnecting = true;
            return true;
        }
        close(connection->fd);
        connection->fd = -1;
        return false;
    }

    void acceptSocks()
    {
        while (true)
        {
            int fd = accept(socksFd, NULL, NULL);
            if (fd < 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    syslog(LOG_WARNING, "accepting SOCKS5 client failed: %s", strerror(errno));
                return;
            }
            prepareSocket(fd);
            if (!setNonblocking(fd))
            {
                close(fd);
                continue;
            }
            Connection *connection = new Connection(this, CONNECTION_SOCKS);
            connection->fd = fd;
            connection->hostConnected = true;
            connections.push_back(connection);
        }
    }

    void attachTcp(Connection *connection)
    {
        tcp_arg(connection->pcb, connection);
        tcp_recv(connection->pcb, tcpReceive);
        tcp_sent(connection->pcb, tcpSent);
        tcp_err(connection->pcb, tcpError);
        tcp_poll(connection->pcb, tcpPoll, 2);
    }

    bool connectLwip(Connection *connection, uint32_t ip, uint16_t port)
    {
        if (!configured)
            return false;
        connection->pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
        if (connection->pcb == NULL)
            return false;
        attachTcp(connection);
        ip_addr_t local;
        ip_addr_copy_from_ip4(local, *netif_ip4_addr(&interface));
        if (tcp_bind(connection->pcb, &local, 0) != ERR_OK)
        {
            abortTcp(connection);
            return false;
        }
        ip_addr_t target;
        IP_ADDR4(&target, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                 (ip >> 8) & 0xff, ip & 0xff);
        err_t result = tcp_connect(connection->pcb, &target, port, tcpConnected);
        if (result != ERR_OK)
        {
            abortTcp(connection);
            return false;
        }
        return true;
    }

    static err_t tcpConnected(void *arg, struct tcp_pcb *, err_t error)
    {
        Connection *connection = static_cast<Connection *>(arg);
        if (error != ERR_OK)
        {
            connection->owner->socksReply(connection, 5);
            return error;
        }
        connection->socksState = SOCKS_STREAM;
        connection->owner->socksReply(connection, 0);
        if (!connection->controlIn.empty())
        {
            appendBytes(connection->upstream, &connection->controlIn[0],
                        connection->controlIn.size());
            connection->controlIn.clear();
        }
        connection->owner->pumpUpstream(connection);
        return ERR_OK;
    }

    static err_t tcpReceive(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                            err_t error)
    {
        Connection *connection = static_cast<Connection *>(arg);
        if (error != ERR_OK)
            return error;
        if (p == NULL)
        {
            connection->lwipReadClosed = true;
            connection->owner->finishIfPossible(connection);
            return ERR_OK;
        }
        size_t queued = connection->networkOut.size() - connection->networkOffset;
        if (queued + p->tot_len > MAX_BRIDGE_BUFFER)
            return ERR_MEM;
        size_t oldSize = connection->networkOut.size();
        connection->networkOut.resize(oldSize + p->tot_len);
        pbuf_copy_partial(p, &connection->networkOut[oldSize], p->tot_len, 0);
        pbuf_free(p);
        (void)pcb;
        return ERR_OK;
    }

    static err_t tcpSent(void *arg, struct tcp_pcb *, u16_t)
    {
        Connection *connection = static_cast<Connection *>(arg);
        connection->owner->pumpUpstream(connection);
        connection->owner->finishIfPossible(connection);
        return ERR_OK;
    }

    static err_t tcpPoll(void *arg, struct tcp_pcb *)
    {
        Connection *connection = static_cast<Connection *>(arg);
        connection->owner->pumpUpstream(connection);
        connection->owner->finishIfPossible(connection);
        return ERR_OK;
    }

    static void tcpError(void *arg, err_t)
    {
        Connection *connection = static_cast<Connection *>(arg);
        connection->pcb = NULL;
        connection->lwipReadClosed = true;
        connection->lwipWriteClosed = true;
        if (connection->kind == CONNECTION_SOCKS &&
            connection->socksState == SOCKS_CONNECTING)
            connection->owner->socksReply(connection, 5);
        else
            connection->closeAfterWrite = true;
    }

    void socksReply(Connection *connection, uint8_t status,
                    uint32_t boundIp = 0, uint16_t boundPort = 0)
    {
        uint8_t reply[10] = {5, status, 0, 1, 0, 0, 0, 0, 0, 0};
        reply[4] = (uint8_t)(boundIp >> 24);
        reply[5] = (uint8_t)(boundIp >> 16);
        reply[6] = (uint8_t)(boundIp >> 8);
        reply[7] = (uint8_t)boundIp;
        reply[8] = (uint8_t)(boundPort >> 8);
        reply[9] = (uint8_t)boundPort;
        appendBytes(connection->controlOut, reply, sizeof(reply));
        if (status != 0)
            connection->closeAfterWrite = true;
    }

    bool resolveSocksTarget(Connection *connection, uint32_t &ip,
                            uint16_t &port, uint8_t &command,
                            size_t &requestLength)
    {
        const vector<char> &data = connection->controlIn;
        if (data.size() < 4)
            return false;
        command = (uint8_t)data[1];
        if ((uint8_t)data[0] != 5 || (command != 1 && command != 3) ||
            (uint8_t)data[2] != 0)
        {
            socksReply(connection, 7);
            requestLength = data.size();
            return true;
        }
        uint8_t type = (uint8_t)data[3];
        string host;
        size_t portOffset;
        if (type == 1)
        {
            if (data.size() < 10)
                return false;
            ip = ((uint32_t)(uint8_t)data[4] << 24) |
                 ((uint32_t)(uint8_t)data[5] << 16) |
                 ((uint32_t)(uint8_t)data[6] << 8) |
                 (uint32_t)(uint8_t)data[7];
            portOffset = 8;
            requestLength = 10;
        }
        else if (type == 3)
        {
            if (data.size() < 5)
                return false;
            size_t nameLength = (uint8_t)data[4];
            if (data.size() < 5 + nameLength + 2)
                return false;
            host.assign(&data[5], &data[5 + nameLength]);
            portOffset = 5 + nameLength;
            requestLength = portOffset + 2;
        }
        else
        {
            if (type == 4 && data.size() < 22)
                return false;
            socksReply(connection, 8);
            requestLength = type == 4 ? 22 : data.size();
            return true;
        }
        port = ((uint16_t)(uint8_t)data[portOffset] << 8) |
               (uint16_t)(uint8_t)data[portOffset + 1];
        if (port == 0 && command != 3)
        {
            socksReply(connection, 1);
            return true;
        }
        if (!host.empty())
        {
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            struct addrinfo *addresses = NULL;
            if (getaddrinfo(host.c_str(), NULL, &hints, &addresses) != 0 ||
                addresses == NULL)
            {
                if (addresses != NULL)
                    freeaddrinfo(addresses);
                socksReply(connection, 4);
                return true;
            }
            sockaddr_in *address = reinterpret_cast<sockaddr_in *>(addresses->ai_addr);
            ip = ntohl(address->sin_addr.s_addr);
            freeaddrinfo(addresses);
        }
        return true;
    }

    void processSocks(Connection *connection)
    {
        while (true)
        {
            if (connection->socksState == SOCKS_GREETING)
            {
                if (connection->controlIn.size() < 2)
                    return;
                size_t count = (uint8_t)connection->controlIn[1];
                if (connection->controlIn.size() < count + 2)
                    return;
                bool acceptedMethod = false;
                const uint8_t wantedMethod = socksUser.empty() ? 0 : 2;
                for (size_t i = 0; i < count; ++i)
                    if ((uint8_t)connection->controlIn[i + 2] == wantedMethod)
                        acceptedMethod = true;
                const uint8_t reply[2] = {5, acceptedMethod ? wantedMethod :
                                                             (uint8_t)0xff};
                appendBytes(connection->controlOut, reply, sizeof(reply));
                connection->controlIn.erase(connection->controlIn.begin(),
                                            connection->controlIn.begin() + count + 2);
                if (!acceptedMethod)
                {
                    connection->closeAfterWrite = true;
                    return;
                }
                connection->socksState = socksUser.empty() ? SOCKS_REQUEST :
                                                             SOCKS_AUTH;
            }
            else if (connection->socksState == SOCKS_AUTH)
            {
                if (connection->controlIn.size() < 2)
                    return;
                const size_t userLength = (uint8_t)connection->controlIn[1];
                if ((uint8_t)connection->controlIn[0] != 1 || userLength == 0)
                {
                    const uint8_t reply[2] = {1, 1};
                    appendBytes(connection->controlOut, reply, sizeof(reply));
                    connection->closeAfterWrite = true;
                    return;
                }
                if (connection->controlIn.size() < 2 + userLength + 1)
                    return;
                const size_t passwordLength =
                    (uint8_t)connection->controlIn[2 + userLength];
                const size_t authLength = 3 + userLength + passwordLength;
                if (connection->controlIn.size() < authLength)
                    return;
                unsigned int difference =
                    (unsigned int)(userLength ^ socksUser.size()) |
                    (unsigned int)(passwordLength ^ socksPassword.size());
                const size_t maxUser = std::max(userLength, socksUser.size());
                const size_t maxPassword = std::max(passwordLength,
                                                    socksPassword.size());
                for (size_t i = 0; i < maxUser; ++i)
                {
                    const uint8_t supplied = i < userLength ?
                        (uint8_t)connection->controlIn[2 + i] : 0;
                    const uint8_t expected = i < socksUser.size() ?
                        (uint8_t)socksUser[i] : 0;
                    difference |= supplied ^ expected;
                }
                for (size_t i = 0; i < maxPassword; ++i)
                {
                    const uint8_t supplied = i < passwordLength ?
                        (uint8_t)connection->controlIn[3 + userLength + i] : 0;
                    const uint8_t expected = i < socksPassword.size() ?
                        (uint8_t)socksPassword[i] : 0;
                    difference |= supplied ^ expected;
                }
                const uint8_t reply[2] = {1, difference == 0 ? (uint8_t)0 :
                                                               (uint8_t)1};
                appendBytes(connection->controlOut, reply, sizeof(reply));
                connection->controlIn.erase(connection->controlIn.begin(),
                                            connection->controlIn.begin() + authLength);
                if (difference != 0)
                {
                    connection->closeAfterWrite = true;
                    return;
                }
                connection->socksState = SOCKS_REQUEST;
            }
            else if (connection->socksState == SOCKS_REQUEST)
            {
                uint32_t ip = 0;
                uint16_t port = 0;
                uint8_t command = 0;
                size_t length = 0;
                if (!resolveSocksTarget(connection, ip, port, command, length))
                    return;
                if (length > connection->controlIn.size())
                    return;
                connection->controlIn.erase(connection->controlIn.begin(),
                                            connection->controlIn.begin() + length);
                if (connection->closeAfterWrite)
                    return;
                if (command == 3)
                {
                    if (!openUdpAssociation(connection))
                        socksReply(connection, 1);
                }
                else
                {
                    connection->socksState = SOCKS_CONNECTING;
                    if (!connectLwip(connection, ip, port))
                        socksReply(connection, 5);
                }
                return;
            }
            else
                return;
        }
    }

    void readHost(Connection *connection)
    {
        char buffer[32768];
        while (true)
        {
            ssize_t length = recv(connection->fd, buffer, sizeof(buffer), 0);
            if (length > 0)
            {
                if (connection->kind == CONNECTION_SOCKS &&
                    connection->socksState != SOCKS_STREAM &&
                    connection->socksState != SOCKS_UDP)
                {
                    appendBytes(connection->controlIn, buffer, (size_t)length);
                    if (connection->controlIn.size() > 65536)
                    {
                        connection->closeAfterWrite = true;
                        return;
                    }
                    processSocks(connection);
                }
                else
                {
                    if (connection->socksState == SOCKS_UDP)
                        continue;
                    appendBytes(connection->upstream, buffer, (size_t)length);
                    pumpUpstream(connection);
                }
                if ((connection->upstream.size() - connection->upstreamOffset) >=
                    MAX_BRIDGE_BUFFER)
                    return;
                continue;
            }
            if (length == 0)
            {
                connection->hostReadClosed = true;
                if (connection->socksState == SOCKS_UDP)
                    connection->closeAfterWrite = true;
                pumpUpstream(connection);
                finishIfPossible(connection);
                return;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                connection->closeAfterWrite = true;
            return;
        }
    }

    void pumpUpstream(Connection *connection)
    {
        if (connection->pcb == NULL)
            return;
        while (connection->upstreamOffset < connection->upstream.size())
        {
            size_t available = connection->upstream.size() - connection->upstreamOffset;
            size_t writable = tcp_sndbuf(connection->pcb);
            size_t chunk = std::min(available, writable);
            if (chunk > 65535)
                chunk = 65535;
            if (chunk == 0)
                break;
            err_t result = tcp_write(connection->pcb,
                                     &connection->upstream[connection->upstreamOffset],
                                     (u16_t)chunk, TCP_WRITE_FLAG_COPY);
            if (result == ERR_MEM)
                break;
            if (result != ERR_OK)
            {
                abortTcp(connection);
                connection->closeAfterWrite = true;
                return;
            }
            consumeBytes(connection->upstream, connection->upstreamOffset, chunk);
        }
        tcp_output(connection->pcb);
        if (connection->hostReadClosed && connection->upstream.empty() &&
            !connection->lwipWriteClosed)
        {
            if (tcp_shutdown(connection->pcb, 0, 1) == ERR_OK)
                connection->lwipWriteClosed = true;
        }
    }

    void writeHost(Connection *connection)
    {
        if (connection->hostConnecting)
        {
            int error = 0;
            socklen_t length = sizeof(error);
            if (getsockopt(connection->fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 ||
                error != 0)
            {
                connection->closeAfterWrite = true;
                abortTcp(connection);
                return;
            }
            connection->hostConnecting = false;
            connection->hostConnected = true;
        }

        while (connection->controlOffset < connection->controlOut.size())
        {
            ssize_t sent = send(connection->fd,
                                &connection->controlOut[connection->controlOffset],
                                connection->controlOut.size() - connection->controlOffset,
                                MSG_NOSIGNAL);
            if (sent > 0)
                consumeBytes(connection->controlOut, connection->controlOffset,
                             (size_t)sent);
            else
            {
                if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    connection->closeAfterWrite = true;
                return;
            }
        }

        while (connection->networkOffset < connection->networkOut.size())
        {
            ssize_t sent = send(connection->fd,
                                &connection->networkOut[connection->networkOffset],
                                connection->networkOut.size() - connection->networkOffset,
                                MSG_NOSIGNAL);
            if (sent > 0)
            {
                consumeBytes(connection->networkOut, connection->networkOffset,
                             (size_t)sent);
                if (connection->pcb != NULL)
                    tcp_recved(connection->pcb, (u16_t)sent);
            }
            else
            {
                if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    connection->closeAfterWrite = true;
                return;
            }
        }
        finishIfPossible(connection);
    }

    void finishIfPossible(Connection *connection)
    {
        if (connection->lwipReadClosed && connection->networkOut.empty() &&
            connection->fd >= 0)
            shutdown(connection->fd, SHUT_WR);

        if (connection->hostReadClosed && connection->lwipReadClosed &&
            connection->upstream.empty() && connection->networkOut.empty())
        {
            if (connection->pcb != NULL)
            {
                tcp_arg(connection->pcb, NULL);
                tcp_recv(connection->pcb, NULL);
                tcp_sent(connection->pcb, NULL);
                tcp_err(connection->pcb, NULL);
                tcp_poll(connection->pcb, NULL, 0);
                if (tcp_close(connection->pcb) != ERR_OK)
                    tcp_abort(connection->pcb);
                connection->pcb = NULL;
            }
            connection->closeAfterWrite = true;
        }
    }

    void abortTcp(Connection *connection)
    {
        if (connection->pcb != NULL)
        {
            tcp_arg(connection->pcb, NULL);
            tcp_recv(connection->pcb, NULL);
            tcp_sent(connection->pcb, NULL);
            tcp_err(connection->pcb, NULL);
            tcp_poll(connection->pcb, NULL, 0);
            tcp_abort(connection->pcb);
            connection->pcb = NULL;
        }
    }

    void destroyConnection(Connection *connection, bool force)
    {
        if (force)
            abortTcp(connection);
        if (connection->fd >= 0)
            close(connection->fd);
        if (connection->udpFd >= 0)
            close(connection->udpFd);
        if (connection->udpPcb != NULL)
            udp_remove(connection->udpPcb);
        delete connection;
    }

    bool openUdpAssociation(Connection *connection)
    {
        connection->udpFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (connection->udpFd < 0 || !setNonblocking(connection->udpFd))
            return false;
        prepareSocket(connection->udpFd);
        sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(socksBindIp);
        local.sin_port = 0;
        if (bind(connection->udpFd, reinterpret_cast<sockaddr *>(&local),
                 sizeof(local)) != 0)
            return false;
        socklen_t localLength = sizeof(local);
        if (getsockname(connection->udpFd, reinterpret_cast<sockaddr *>(&local),
                        &localLength) != 0)
            return false;

        connection->udpPcb = udp_new_ip_type(IPADDR_TYPE_V4);
        if (connection->udpPcb == NULL)
            return false;
        ip_addr_t localVpn;
        ip_addr_copy_from_ip4(localVpn, *netif_ip4_addr(&interface));
        if (udp_bind(connection->udpPcb, &localVpn, 0) != ERR_OK)
            return false;
        udp_recv(connection->udpPcb, receiveUdpFromVpn, connection);
        connection->socksState = SOCKS_UDP;
        socksReply(connection, 0, socksBindIp, ntohs(local.sin_port));
        return true;
    }

    static void receiveUdpFromVpn(void *arg, struct udp_pcb *, struct pbuf *p,
                                  const ip_addr_t *address, u16_t port)
    {
        Connection *connection = static_cast<Connection *>(arg);
        if (!connection->udpClientKnown || connection->udpFd < 0)
        {
            pbuf_free(p);
            return;
        }
        uint32_t ip = ntohl(ip4_addr_get_u32(ip_2_ip4(address)));
        vector<char> datagram(10 + p->tot_len);
        datagram[0] = datagram[1] = datagram[2] = 0;
        datagram[3] = 1;
        datagram[4] = (char)(ip >> 24);
        datagram[5] = (char)(ip >> 16);
        datagram[6] = (char)(ip >> 8);
        datagram[7] = (char)ip;
        datagram[8] = (char)(port >> 8);
        datagram[9] = (char)port;
        pbuf_copy_partial(p, &datagram[10], p->tot_len, 0);
        pbuf_free(p);
        sendto(connection->udpFd, &datagram[0], datagram.size(), MSG_NOSIGNAL,
               reinterpret_cast<sockaddr *>(&connection->udpClient),
               sizeof(connection->udpClient));
    }

    bool parseUdpTarget(const char *data, size_t length, uint32_t &ip,
                        uint16_t &port, size_t &headerLength)
    {
        if (length < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0)
            return false;
        uint8_t type = (uint8_t)data[3];
        string host;
        size_t portOffset;
        if (type == 1)
        {
            if (length < 10)
                return false;
            ip = ((uint32_t)(uint8_t)data[4] << 24) |
                 ((uint32_t)(uint8_t)data[5] << 16) |
                 ((uint32_t)(uint8_t)data[6] << 8) |
                 (uint32_t)(uint8_t)data[7];
            portOffset = 8;
        }
        else if (type == 3)
        {
            if (length < 5)
                return false;
            size_t nameLength = (uint8_t)data[4];
            if (length < 5 + nameLength + 2)
                return false;
            host.assign(data + 5, data + 5 + nameLength);
            portOffset = 5 + nameLength;
        }
        else
            return false;
        port = ((uint16_t)(uint8_t)data[portOffset] << 8) |
               (uint16_t)(uint8_t)data[portOffset + 1];
        headerLength = portOffset + 2;
        if (port == 0)
            return false;
        if (!host.empty())
        {
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            struct addrinfo *addresses = NULL;
            if (getaddrinfo(host.c_str(), NULL, &hints, &addresses) != 0 ||
                addresses == NULL)
            {
                if (addresses != NULL)
                    freeaddrinfo(addresses);
                return false;
            }
            sockaddr_in *resolved = reinterpret_cast<sockaddr_in *>(addresses->ai_addr);
            ip = ntohl(resolved->sin_addr.s_addr);
            freeaddrinfo(addresses);
        }
        return true;
    }

    void readUdpFromHost(Connection *connection)
    {
        char data[65535];
        sockaddr_in source;
        socklen_t sourceLength = sizeof(source);
        ssize_t length = recvfrom(connection->udpFd, data, sizeof(data), 0,
                                  reinterpret_cast<sockaddr *>(&source),
                                  &sourceLength);
        if (length <= 0)
            return;
        if (connection->udpClientKnown &&
            (source.sin_addr.s_addr != connection->udpClient.sin_addr.s_addr ||
             source.sin_port != connection->udpClient.sin_port))
            return;
        connection->udpClient = source;
        connection->udpClientKnown = true;

        uint32_t ip;
        uint16_t port;
        size_t headerLength;
        if (!parseUdpTarget(data, (size_t)length, ip, port, headerLength) ||
            headerLength >= (size_t)length)
            return;
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT,
                                    (u16_t)((size_t)length - headerLength), PBUF_RAM);
        if (p == NULL || pbuf_take(p, data + headerLength,
                                   (u16_t)((size_t)length - headerLength)) != ERR_OK)
        {
            if (p != NULL)
                pbuf_free(p);
            return;
        }
        ip_addr_t target;
        IP_ADDR4(&target, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                 (ip >> 8) & 0xff, ip & 0xff);
        udp_sendto(connection->udpPcb, p, &target, port);
        pbuf_free(p);
    }

    int addFileDescriptors(fd_set &readSet, fd_set &writeSet, int maxFd)
    {
        if (socksFd >= 0)
        {
            FD_SET(socksFd, &readSet);
            maxFd = std::max(maxFd, socksFd);
        }
        for (size_t i = 0; i < connections.size(); ++i)
        {
            Connection *connection = connections[i];
            if (connection->fd < 0)
            {
                if (connection->udpFd < 0)
                    continue;
            }
            bool streamReady = connection->kind == CONNECTION_SHARE ||
                               connection->socksState == SOCKS_STREAM;
            if (connection->fd >= 0)
            {
                if (!connection->hostReadClosed && !connection->hostConnecting &&
                    (!streamReady || connection->upstream.size() - connection->upstreamOffset <
                                     MAX_BRIDGE_BUFFER))
                    FD_SET(connection->fd, &readSet);
                if (connection->hostConnecting || !connection->controlOut.empty() ||
                    !connection->networkOut.empty())
                    FD_SET(connection->fd, &writeSet);
                maxFd = std::max(maxFd, connection->fd);
            }
            if (connection->udpFd >= 0)
            {
                FD_SET(connection->udpFd, &readSet);
                maxFd = std::max(maxFd, connection->udpFd);
            }
        }
        return maxFd;
    }

    void handleFileDescriptors(fd_set &readSet, fd_set &writeSet)
    {
        if (socksFd >= 0 && FD_ISSET(socksFd, &readSet))
            acceptSocks();
        for (size_t i = 0; i < connections.size(); ++i)
        {
            Connection *connection = connections[i];
            if (connection->udpFd >= 0 && FD_ISSET(connection->udpFd, &readSet))
                readUdpFromHost(connection);
            if (connection->fd >= 0 && FD_ISSET(connection->fd, &writeSet))
                writeHost(connection);
            if (connection->fd >= 0 && FD_ISSET(connection->fd, &readSet))
                readHost(connection);
            pumpUpstream(connection);
        }

        for (size_t i = 0; i < connections.size(); )
        {
            Connection *connection = connections[i];
            bool outputEmpty = connection->controlOut.empty() &&
                               connection->networkOut.empty();
            if (connection->closeAfterWrite && outputEmpty)
            {
                destroyConnection(connection, true);
                connections.erase(connections.begin() + i);
            }
            else
                ++i;
        }
    }

    UserspaceNetworkObserver *observer;
    int mtu;
    string socksAddress;
    vector<SharePort> sharePorts;
    string socksUser;
    string socksPassword;
    int socksFd;
    uint32_t socksBindIp;
    bool configured;
    struct netif interface;
    vector<Connection *> connections;
    vector<SharedListener *> sharedListeners;
};

UserspaceNetwork::UserspaceNetwork(UserspaceNetworkObserver *observer, int mtu,
                                   const string &socksAddress,
                                   const vector<SharePort> &sharePorts,
                                   const string &socksUser,
                                   const string &socksPassword)
    : impl(new Impl(observer, mtu, socksAddress, sharePorts,
                    socksUser, socksPassword))
{
}

UserspaceNetwork::~UserspaceNetwork()
{
    delete impl;
}

void UserspaceNetwork::configure(uint32_t ip, uint32_t gateway)
{
    impl->configure(ip, gateway);
}

void UserspaceNetwork::setMtu(int mtu)
{
    impl->setMtu(mtu);
}

void UserspaceNetwork::ingest(const char *packet, int length)
{
    impl->ingest(packet, length);
}

int UserspaceNetwork::addFileDescriptors(fd_set &readSet, fd_set &writeSet,
                                         int maxFd)
{
    return impl->addFileDescriptors(readSet, writeSet, maxFd);
}

void UserspaceNetwork::handleFileDescriptors(fd_set &readSet, fd_set &writeSet)
{
    impl->handleFileDescriptors(readSet, writeSet);
}

void UserspaceNetwork::tick()
{
    sys_check_timeouts();
}

bool UserspaceNetwork::parseEndpoint(const string &text, uint32_t &ip,
                                     uint16_t &port, string &error)
{
    size_t colon = text.rfind(':');
    if (colon == string::npos || colon == 0 || colon + 1 == text.size())
    {
        error = "expected IPv4:port";
        return false;
    }
    string host = text.substr(0, colon);
    in_addr address;
    if (inet_pton(AF_INET, host.c_str(), &address) != 1)
    {
        error = "expected a numeric IPv4 address";
        return false;
    }
    if (!parsePort(text.substr(colon + 1), port))
    {
        error = "port must be between 1 and 65535";
        return false;
    }
    ip = ntohl(address.s_addr);
    return true;
}

bool UserspaceNetwork::parseSharePorts(const string &text,
                                       vector<SharePort> &ports,
                                       string &error)
{
    ports.clear();
    std::set<uint16_t> listeners;
    size_t start = 0;
    while (start <= text.size())
    {
        size_t comma = text.find(',', start);
        string token = text.substr(start, comma == string::npos ? string::npos :
                                                       comma - start);
        if (token.empty())
        {
            error = "empty port mapping";
            return false;
        }
        SharePort mapping;
        mapping.targetIp = 0x7f000001u;
        size_t equals = token.find('=');
        string listenText = token.substr(0, equals);
        if (!parsePort(listenText, mapping.listenPort))
        {
            error = string("invalid listening port: ") + listenText;
            return false;
        }
        if (equals == string::npos)
            mapping.targetPort = mapping.listenPort;
        else
        {
            string target = token.substr(equals + 1);
            if (!parseEndpoint(target, mapping.targetIp, mapping.targetPort, error))
            {
                error = string("invalid mapping '") + token + "': " + error;
                return false;
            }
        }
        if (!listeners.insert(mapping.listenPort).second)
        {
            error = string("duplicate listening port: ") + listenText;
            return false;
        }
        ports.push_back(mapping);
        if (comma == string::npos)
            break;
        start = comma + 1;
    }
    return !ports.empty();
}
