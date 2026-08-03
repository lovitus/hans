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

#include "echo.h"
#include "exception.h"
#include "config.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#ifdef WIN32
#include <w32api/windows.h>
#include <pthread.h>
#include <fcntl.h>
#include <deque>

namespace
{
    // IcmpParseReplies uses the 32-bit wire-compatible reply layout even in a
    // 64-bit process.  Keeping these fields explicitly 32-bit also lets the
    // same parser work in the x86 Cygwin build.
    struct HansIpOptionInformation32
    {
        unsigned char ttl;
        unsigned char tos;
        unsigned char flags;
        unsigned char optionsSize;
        uint32_t optionsData;
    };

    struct HansIcmpEchoReply32
    {
        DWORD address;
        DWORD status;
        DWORD roundTripTime;
        unsigned short dataSize;
        unsigned short reserved;
        uint32_t data;
        HansIpOptionInformation32 options;
    };

    struct HansIpv6AddressEx
    {
        unsigned short port;
        unsigned short padding;
        DWORD flowInfo;
        unsigned short address[8];
        DWORD scopeId;
    };

    struct HansIcmp6EchoReply
    {
        HansIpv6AddressEx address;
        DWORD status;
        unsigned int roundTripTime;
    };

    const DWORD HANS_IP_SUCCESS = 0;
}

class Echo::WindowsBackend
{
public:
    struct Request
    {
        std::vector<char> payload;
        std::vector<char> replyBuffer;
        Echo::Address address;
        uint16_t id;
        uint16_t seq;
        HANDLE event;
    };

    struct Pending
    {
        std::vector<char> payload;
        Echo::Address address;
        uint16_t id;
        uint16_t seq;
    };

    typedef HANDLE (WINAPI *CreateFileFunction)(void);
    typedef BOOL (WINAPI *CloseHandleFunction)(HANDLE);
    typedef DWORD (WINAPI *SendEchoFunction)(HANDLE, HANDLE, FARPROC, void *,
                                              DWORD, void *, unsigned short,
                                              void *, void *,
                                              DWORD, DWORD);
    typedef DWORD (WINAPI *ParseRepliesFunction)(void *, DWORD);
    typedef DWORD (WINAPI *SendEcho6Function)(HANDLE, HANDLE, FARPROC, void *,
                                               void *, void *, void *,
                                               unsigned short, void *, void *,
                                               DWORD, DWORD);

    WindowsBackend(int maxPayloadSize)
        : library(NULL), icmpHandle(INVALID_HANDLE_VALUE),
          icmp6Handle(INVALID_HANDLE_VALUE), wakeEvent(NULL),
          stopping(false), threadStarted(false), createFileFunction(NULL),
          closeHandleFunction(NULL), sendEchoFunction(NULL),
          parseRepliesFunction(NULL), sendEcho6Function(NULL),
          parseReplies6Function(NULL),
          replyBufferSize(sizeof(HansIcmp6EchoReply) + maxPayloadSize + 32),
          requestCount(0)
    {
        pipeFds[0] = pipeFds[1] = -1;
        library = LoadLibraryA("iphlpapi.dll");
        if (library == NULL)
            throw Exception("loading Windows ICMP API", true);
        createFileFunction = reinterpret_cast<CreateFileFunction>(
            GetProcAddress(library, "IcmpCreateFile"));
        closeHandleFunction = reinterpret_cast<CloseHandleFunction>(
            GetProcAddress(library, "IcmpCloseHandle"));
        sendEchoFunction = reinterpret_cast<SendEchoFunction>(
            GetProcAddress(library, "IcmpSendEcho2"));
        parseRepliesFunction = reinterpret_cast<ParseRepliesFunction>(
            GetProcAddress(library, "IcmpParseReplies"));
        CreateFileFunction createFile6Function =
            reinterpret_cast<CreateFileFunction>(
                GetProcAddress(library, "Icmp6CreateFile"));
        sendEcho6Function = reinterpret_cast<SendEcho6Function>(
            GetProcAddress(library, "Icmp6SendEcho2"));
        parseReplies6Function = reinterpret_cast<ParseRepliesFunction>(
            GetProcAddress(library, "Icmp6ParseReplies"));
        if (createFileFunction == NULL || closeHandleFunction == NULL ||
            sendEchoFunction == NULL || parseRepliesFunction == NULL)
            throw Exception("resolving Windows ICMP API");

        icmpHandle = createFileFunction();
        if (icmpHandle == INVALID_HANDLE_VALUE)
            throw Exception("creating Windows ICMP handle", true);
        if (createFile6Function != NULL && sendEcho6Function != NULL &&
            parseReplies6Function != NULL)
            icmp6Handle = createFile6Function();
        wakeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (wakeEvent == NULL || pipe(pipeFds) != 0)
            throw Exception("creating Windows ICMP notification channel", true);
        fcntl(pipeFds[0], F_SETFL, fcntl(pipeFds[0], F_GETFL, 0) | O_NONBLOCK);
        fcntl(pipeFds[1], F_SETFL, fcntl(pipeFds[1], F_GETFL, 0) | O_NONBLOCK);
        pthread_mutex_init(&mutex, NULL);
        if (pthread_create(&thread, NULL, threadEntry, this) != 0)
            throw Exception("creating Windows ICMP worker", true);
        threadStarted = true;
    }

    ~WindowsBackend()
    {
        pthread_mutex_lock(&mutex);
        stopping = true;
        pthread_mutex_unlock(&mutex);
        if (wakeEvent != NULL)
            SetEvent(wakeEvent);
        if (threadStarted)
            pthread_join(thread, NULL);

        clearPending(queued);
        clearPending(freePending);
        clearRequests(active);
        clearRequests(completed);
        clearRequests(freeRequests);
        if (pipeFds[0] >= 0)
            close(pipeFds[0]);
        if (pipeFds[1] >= 0)
            close(pipeFds[1]);
        if (wakeEvent != NULL)
            CloseHandle(wakeEvent);
        if (icmpHandle != INVALID_HANDLE_VALUE && closeHandleFunction != NULL)
            closeHandleFunction(icmpHandle);
        if (icmp6Handle != INVALID_HANDLE_VALUE && closeHandleFunction != NULL)
            closeHandleFunction(icmp6Handle);
        if (library != NULL)
            FreeLibrary(library);
        pthread_mutex_destroy(&mutex);
    }

    int getFd() const
    {
        return pipeFds[0];
    }

    void send(const char *payload, int length, const Echo::Address &address,
              uint16_t id, uint16_t seq)
    {
        pthread_mutex_lock(&mutex);
        Pending *pending;
        if (freePending.empty())
            pending = new Pending;
        else
        {
            pending = freePending.front();
            freePending.pop_front();
        }
        pthread_mutex_unlock(&mutex);

        pending->payload.assign(payload, payload + length);
        pending->address = address;
        pending->id = id;
        pending->seq = seq;

        pthread_mutex_lock(&mutex);
        queued.push_back(pending);
        pthread_mutex_unlock(&mutex);
        SetEvent(wakeEvent);
    }

    bool receive(char *payload, size_t payloadCapacity, int &payloadLength,
                 Echo::Address &address, uint16_t &id, uint16_t &seq)
    {
        payloadLength = 0;
        char notification;
        read(pipeFds[0], &notification, 1);
        pthread_mutex_lock(&mutex);
        if (completed.empty())
        {
            pthread_mutex_unlock(&mutex);
            return false;
        }
        Request *request = completed.front();
        completed.pop_front();
        pthread_mutex_unlock(&mutex);

        bool ipv6 = request->address.family() == AF_INET6;
        DWORD replyCount = (ipv6 ? parseReplies6Function : parseRepliesFunction)(
            &request->replyBuffer[0], (DWORD)request->replyBuffer.size());
        if (ipv6)
        {
            HansIcmp6EchoReply *reply =
                reinterpret_cast<HansIcmp6EchoReply *>(
                    &request->replyBuffer[0]);
            bool valid = replyCount > 0 && reply->status == HANS_IP_SUCCESS &&
                request->replyBuffer.size() >= sizeof(*reply) +
                                                     request->payload.size() &&
                request->payload.size() <= payloadCapacity;
            if (valid)
            {
                const char *data = &request->replyBuffer[sizeof(*reply)];
                memcpy(payload, data, request->payload.size());
                payloadLength = (int)request->payload.size();
                address = request->address;
                id = request->id;
                seq = request->seq;
            }
            recycleRequest(request);
            return valid;
        }
        HansIcmpEchoReply32 *reply = reinterpret_cast<HansIcmpEchoReply32 *>(
            &request->replyBuffer[0]);
        const char *bufferBegin = &request->replyBuffer[0];
        uintptr_t bufferAddress = reinterpret_cast<uintptr_t>(bufferBegin);
        uintptr_t bufferEndAddress = bufferAddress + request->replyBuffer.size();
        uintptr_t dataAddress = (uintptr_t)reply->data;
#if UINTPTR_MAX > 0xffffffffU
        // POINTER_32 contains the low half of an address in a 64-bit reply.
        // Reply data lives in ReplyBuffer, so recover the buffer's high half.
        dataAddress |= (bufferAddress & ~((uintptr_t)0xffffffffU));
#endif
        bool dataInBuffer = dataAddress >= bufferAddress &&
                            dataAddress <= bufferEndAddress &&
                            bufferEndAddress - dataAddress >= reply->dataSize;
        const char *data = reinterpret_cast<const char *>(dataAddress);
        if (!dataInBuffer &&
            request->replyBuffer.size() >= sizeof(HansIcmpEchoReply32) +
                                                   reply->dataSize)
        {
            // The no-options layout is deterministic for our requests.  This
            // also covers implementations that leave POINTER_32 unusable to a
            // non-MSVC 64-bit compiler.
            data = bufferBegin + sizeof(HansIcmpEchoReply32);
            dataInBuffer = true;
        }
        bool valid = replyCount > 0 && reply->status == HANS_IP_SUCCESS &&
                     dataInBuffer && reply->dataSize <= payloadCapacity;
        if (valid)
        {
            memcpy(payload, data, reply->dataSize);
            payloadLength = (int)reply->dataSize;
            address = Echo::Address::ipv4(ntohl(reply->address));
            id = request->id;
            seq = request->seq;
        }
        recycleRequest(request);
        return valid;
    }

private:
    static void *threadEntry(void *context)
    {
        static_cast<WindowsBackend *>(context)->run();
        return NULL;
    }

    void startQueued()
    {
        while (active.size() < WINDOWS_ICMP_MAX_PENDING)
        {
            pthread_mutex_lock(&mutex);
            if (queued.empty() ||
                (freeRequests.empty() &&
                 requestCount >= WINDOWS_ICMP_MAX_PENDING * 2))
            {
                pthread_mutex_unlock(&mutex);
                break;
            }
            Pending *pending = queued.front();
            queued.pop_front();
            Request *request = NULL;
            if (!freeRequests.empty())
            {
                request = freeRequests.front();
                freeRequests.pop_front();
            }
            else
                ++requestCount;
            pthread_mutex_unlock(&mutex);

            if (request == NULL)
            {
                request = new Request;
                // A short poll request can carry a full tunnel packet in its
                // reply, so every reusable slot owns a maximum-sized buffer.
                request->replyBuffer.resize(replyBufferSize);
                request->event = CreateEvent(NULL, FALSE, FALSE, NULL);
                if (request->event == NULL)
                {
                    delete request;
                    pthread_mutex_lock(&mutex);
                    --requestCount;
                    queued.push_front(pending);
                    pthread_mutex_unlock(&mutex);
                    break;
                }
            }

            request->payload.swap(pending->payload);
            request->address = pending->address;
            request->id = pending->id;
            request->seq = pending->seq;
            recyclePending(pending);
            ResetEvent(request->event);

            DWORD result;
            if (request->address.family() == AF_INET6)
            {
                HansIpv6AddressEx source;
                memset(&source, 0, sizeof(source));
                HansIpv6AddressEx destination;
                memset(&destination, 0, sizeof(destination));
                const struct sockaddr_in6 *address =
                    reinterpret_cast<const struct sockaddr_in6 *>(
                        request->address.sockaddrValue());
                memcpy(destination.address, &address->sin6_addr,
                       sizeof(destination.address));
                destination.scopeId = address->sin6_scope_id;
                result = icmp6Handle == INVALID_HANDLE_VALUE ? 0 :
                    sendEcho6Function(
                        icmp6Handle, request->event, NULL, NULL, &source,
                        &destination,
                        request->payload.empty() ? NULL : &request->payload[0],
                        (unsigned short)request->payload.size(), NULL,
                        &request->replyBuffer[0],
                        (DWORD)request->replyBuffer.size(),
                        WINDOWS_ICMP_REQUEST_TIMEOUT_MS);
            }
            else
                result = sendEchoFunction(
                    icmpHandle, request->event, NULL, NULL,
                    htonl(request->address.ipv4Value()),
                    request->payload.empty() ? NULL : &request->payload[0],
                    (unsigned short)request->payload.size(), NULL,
                    &request->replyBuffer[0],
                    (DWORD)request->replyBuffer.size(),
                    WINDOWS_ICMP_REQUEST_TIMEOUT_MS);
            if (result > 0)
                complete(request);
            else if (GetLastError() == ERROR_IO_PENDING)
                active.push_back(request);
            else
                recycleRequest(request);
        }
    }

    void recyclePending(Pending *pending)
    {
        pending->payload.clear();
        pthread_mutex_lock(&mutex);
        bool keep = freePending.size() < WINDOWS_ICMP_MAX_PENDING * 2;
        if (keep)
            freePending.push_back(pending);
        pthread_mutex_unlock(&mutex);
        if (!keep)
            delete pending;
    }

    void recycleRequest(Request *request)
    {
        request->payload.clear();
        pthread_mutex_lock(&mutex);
        freeRequests.push_back(request);
        bool wake = !queued.empty();
        pthread_mutex_unlock(&mutex);
        if (wake)
            SetEvent(wakeEvent);
    }

    void complete(Request *request)
    {
        pthread_mutex_lock(&mutex);
        completed.push_back(request);
        pthread_mutex_unlock(&mutex);
        char notification = 1;
        write(pipeFds[1], &notification, 1);
    }

    void run()
    {
        std::vector<HANDLE> handles;
        handles.reserve(WINDOWS_ICMP_MAX_PENDING + 1);
        while (true)
        {
            pthread_mutex_lock(&mutex);
            bool shouldStop = stopping;
            pthread_mutex_unlock(&mutex);
            if (shouldStop)
                break;

            startQueued();
            handles.clear();
            handles.push_back(wakeEvent);
            for (size_t i = 0; i < active.size(); ++i)
                handles.push_back(active[i]->event);
            DWORD result = WaitForMultipleObjects((DWORD)handles.size(),
                                                   &handles[0], FALSE, INFINITE);
            if (result == WAIT_OBJECT_0)
            {
                ResetEvent(wakeEvent);
                continue;
            }
            size_t index = (size_t)(result - WAIT_OBJECT_0);
            if (index >= 1 && index <= active.size())
            {
                Request *request = active[index - 1];
                active.erase(active.begin() + index - 1);
                complete(request);
            }
        }
    }

    void clearRequests(std::deque<Request *> &requests)
    {
        while (!requests.empty())
        {
            CloseHandle(requests.front()->event);
            delete requests.front();
            requests.pop_front();
        }
    }

    void clearPending(std::deque<Pending *> &requests)
    {
        while (!requests.empty())
        {
            delete requests.front();
            requests.pop_front();
        }
    }

    HMODULE library;
    HANDLE icmpHandle;
    HANDLE icmp6Handle;
    HANDLE wakeEvent;
    int pipeFds[2];
    pthread_t thread;
    pthread_mutex_t mutex;
    bool stopping;
    bool threadStarted;
    CreateFileFunction createFileFunction;
    CloseHandleFunction closeHandleFunction;
    SendEchoFunction sendEchoFunction;
    ParseRepliesFunction parseRepliesFunction;
    SendEcho6Function sendEcho6Function;
    ParseRepliesFunction parseReplies6Function;
    size_t replyBufferSize;
    size_t requestCount;
    std::deque<Pending *> queued;
    std::deque<Pending *> freePending;
    std::deque<Request *> active;
    std::deque<Request *> completed;
    std::deque<Request *> freeRequests;
};
#endif
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

typedef ip IpHeader;

namespace
{
    const int NETWORK_HEADER_RESERVE = 40;
}

Echo::Address::Address() : addressLength(0)
{
    memset(&storage, 0, sizeof(storage));
}

Echo::Address::Address(const struct sockaddr *address, socklen_t length)
    : addressLength(length > sizeof(storage) ? sizeof(storage) : length)
{
    memset(&storage, 0, sizeof(storage));
    memcpy(&storage, address, addressLength);
}

Echo::Address Echo::Address::ipv4(uint32_t hostOrderAddress)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(hostOrderAddress);
    return Address((const struct sockaddr *)&address, sizeof(address));
}

int Echo::Address::family() const
{
    return addressLength == 0 ? AF_UNSPEC :
           ((const struct sockaddr *)&storage)->sa_family;
}

bool Echo::Address::isIpv4() const
{
    return family() == AF_INET;
}

uint32_t Echo::Address::ipv4Value() const
{
    if (!isIpv4()) return 0;
    return ntohl(((const struct sockaddr_in *)&storage)->sin_addr.s_addr);
}

const struct sockaddr *Echo::Address::sockaddrValue() const
{
    return (const struct sockaddr *)&storage;
}

std::string Echo::Address::format() const
{
    char host[NI_MAXHOST];
    if (addressLength == 0 ||
        getnameinfo(sockaddrValue(), addressLength, host, sizeof(host),
                    NULL, 0, NI_NUMERICHOST) != 0)
        return "unknown";
    return host;
}

bool Echo::Address::operator==(const Address &other) const
{
    if (family() != other.family()) return false;
    if (family() == AF_INET)
        return ((const struct sockaddr_in *)&storage)->sin_addr.s_addr ==
               ((const struct sockaddr_in *)&other.storage)->sin_addr.s_addr;
    if (family() == AF_INET6)
    {
        const struct sockaddr_in6 *left =
            (const struct sockaddr_in6 *)&storage;
        const struct sockaddr_in6 *right =
            (const struct sockaddr_in6 *)&other.storage;
        return left->sin6_scope_id == right->sin6_scope_id &&
               memcmp(&left->sin6_addr, &right->sin6_addr,
                      sizeof(left->sin6_addr)) == 0;
    }
    return false;
}

Echo::Echo(int maxPayloadSize, bool preferUnprivileged)
{
    datagramSocket = false;
    ipv6DatagramSocket = false;
    fd = -1;
    ipv6Fd = -1;
#ifdef LINUX
    pendingSendCount = 0;
    activeReceiveBuffer = 0;
    batchActive = false;
    sendmmsgAvailable = true;
    recvmmsgAvailable = true;
    sendBatchObserved = false;
    receiveBatchObserved = false;
#endif
#ifdef WIN32
    windowsBackend = NULL;
    if (preferUnprivileged)
    {
        windowsBackend = new WindowsBackend(maxPayloadSize);
        fd = windowsBackend->getFd();
        bufferSize = maxPayloadSize + headerSize();
        sendBuffer.resize(bufferSize);
        receiveBuffer.resize(bufferSize);
        syslog(LOG_INFO, "using Windows ICMP helper API");
        return;
    }
#endif

    if (preferUnprivileged)
    {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (fd >= 0)
        {
            datagramSocket = true;
            syslog(LOG_INFO, "using unprivileged ICMP ping socket");
        }
    }

    if (fd == -1)
        fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd == -1)
    {
        if (preferUnprivileged)
            throw Exception("creating ICMP socket (the OS did not permit either a ping socket or a raw socket)", true);
        throw Exception("creating icmp socket", true);
    }

    if (preferUnprivileged)
    {
        ipv6Fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if (ipv6Fd >= 0)
            ipv6DatagramSocket = true;
    }
    if (ipv6Fd == -1)
        ipv6Fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    bufferSize = maxPayloadSize + headerSize();
#ifdef LINUX
    for (int i = 0; i < MAX_BATCH_PACKETS; ++i)
    {
        sendBuffers[i].resize(bufferSize);
        receiveBuffers[i].resize(bufferSize);
    }
    syslog(LOG_INFO, "using single-threaded Linux batched ICMP I/O");
#else
    sendBuffer.resize(bufferSize);
    receiveBuffer.resize(bufferSize);
#endif
}

Echo::~Echo()
{
#ifdef WIN32
    if (windowsBackend != NULL)
    {
        delete windowsBackend;
        return;
    }
#endif
    close(fd);
    if (ipv6Fd >= 0)
        close(ipv6Fd);
}

int Echo::headerSize()
{
    return NETWORK_HEADER_RESERVE + sizeof(EchoHeader);
}

void Echo::send(int payloadLength, const Address &address, bool reply,
                uint16_t id, uint16_t seq)
{
#ifdef WIN32
    if (windowsBackend != NULL)
    {
        if (reply)
            syslog(LOG_WARNING, "Windows ICMP helper cannot send echo replies");
        else
            windowsBackend->send(sendPayloadBuffer(), payloadLength,
                                 address, id, seq);
        return;
    }
#endif
    if (payloadLength + headerSize() > bufferSize)
        throw Exception("packet too big");

    int sendFd = address.family() == AF_INET6 ? ipv6Fd : fd;
    if (sendFd < 0)
        throw Exception("the operating system did not provide an ICMPv6 socket");
#ifdef LINUX
    if (pendingSendCount >= MAX_BATCH_PACKETS)
        flushLinuxBatch();
    int bufferIndex = pendingSendCount;
    char *rawBuffer = &sendBuffers[bufferIndex][0];
#else
    int bufferIndex = 0;
    char *rawBuffer = &sendBuffer[0];
#endif
    EchoHeader *header = (EchoHeader *)(rawBuffer + NETWORK_HEADER_RESERVE);
    header->type = address.family() == AF_INET6 ?
                   (reply ? 129 : 128) : (reply ? 0 : 8);
    header->code = 0;
    header->id = htons(id);
    header->seq = htons(seq);
    header->chksum = 0;
    if (address.family() == AF_INET)
        header->chksum = icmpChecksum(rawBuffer + NETWORK_HEADER_RESERVE,
                                     payloadLength + sizeof(EchoHeader));

    int wireLength = payloadLength + sizeof(EchoHeader);
#ifdef LINUX
    if (batchActive)
    {
        pendingSends[bufferIndex].address = address;
        pendingSends[bufferIndex].fd = sendFd;
        pendingSends[bufferIndex].wireLength = wireLength;
        ++pendingSendCount;
        if (pendingSendCount == MAX_BATCH_PACKETS)
            flushLinuxBatch();
        return;
    }
#endif
    sendOne(sendFd, bufferIndex, wireLength, address);
}

int Echo::receive(int readyFd, Address &address, bool &reply,
                  uint16_t &id, uint16_t &seq)
{
#ifdef WIN32
    if (windowsBackend != NULL)
    {
        int payloadLength;
        if (!windowsBackend->receive(
                receivePayloadBuffer(), receiveBuffer.size() - headerSize(),
                payloadLength, address, id, seq))
            return -1;
        reply = true;
        return payloadLength;
    }
#endif
    struct sockaddr_storage source;
    socklen_t sourceAddressLength = sizeof(source);

#ifdef LINUX
    activeReceiveBuffer = 0;
    char *target = &receiveBuffers[0][0];
#else
    char *target = &receiveBuffer[0];
#endif
    int dataLength = recvfrom(readyFd, target, bufferSize, 0,
                              (struct sockaddr *)&source,
                              &sourceAddressLength);
    if (dataLength == -1)
    {
        syslog(LOG_ERR, "error receiving icmp packet: %s", strerror(errno));
        return -1;
    }

    ReceivedPacket packet;
    int parsed = parseReceivedPacket(0, dataLength,
                                     (const struct sockaddr *)&source,
                                     sourceAddressLength, packet);
    if (parsed < 0)
        return -1;
    address = packet.address;
    reply = packet.reply;
    id = packet.id;
    seq = packet.seq;
    return parsed;
}

int Echo::parseReceivedPacket(int bufferIndex, int dataLength,
                              const struct sockaddr *source,
                              socklen_t sourceAddressLength,
                              ReceivedPacket &packet)
{
#ifdef LINUX
    char *target = &receiveBuffers[bufferIndex][0];
#else
    (void)bufferIndex;
    char *target = &receiveBuffer[0];
#endif

    packet.address = Address(source, sourceAddressLength);
    int icmpOffset = 0;
    if (dataLength > 0 && ((unsigned char)target[0] >> 4) == 4)
    {
        if (dataLength < (int)sizeof(IpHeader)) return -1;
        icmpOffset = ((unsigned char)target[0] & 15) * 4;
    }
    else if (dataLength > 0 && ((unsigned char)target[0] >> 4) == 6)
        icmpOffset = 40;
    if (icmpOffset < 0 || dataLength - icmpOffset < (int)sizeof(EchoHeader))
        return -1;
    int icmpLength = dataLength - icmpOffset;
    memmove(target + NETWORK_HEADER_RESERVE, target + icmpOffset, icmpLength);

    EchoHeader *header = (EchoHeader *)(target + NETWORK_HEADER_RESERVE);
    bool ipv6 = packet.address.family() == AF_INET6;
    if ((!ipv6 && header->type != 0 && header->type != 8) ||
        (ipv6 && header->type != 128 && header->type != 129) ||
        header->code != 0)
        return -1;

    packet.reply = ipv6 ? header->type == 129 : header->type == 0;
    packet.id = ntohs(header->id);
    packet.seq = ntohs(header->seq);
    packet.length = icmpLength - sizeof(EchoHeader);
    packet.bufferIndex = bufferIndex;

    return packet.length;
}

int Echo::receiveMany(int readyFd, ReceivedPacket *packets, int maximum)
{
    if (packets == NULL || maximum <= 0)
        return 0;
    if (maximum > MAX_BATCH_PACKETS)
        maximum = MAX_BATCH_PACKETS;
#ifdef LINUX
    if (recvmmsgAvailable)
    {
        struct mmsghdr messages[MAX_BATCH_PACKETS];
        struct iovec vectors[MAX_BATCH_PACKETS];
        struct sockaddr_storage sources[MAX_BATCH_PACKETS];
        memset(messages, 0, sizeof(messages));
        memset(vectors, 0, sizeof(vectors));
        memset(sources, 0, sizeof(sources));
        for (int i = 0; i < maximum; ++i)
        {
            vectors[i].iov_base = &receiveBuffers[i][0];
            vectors[i].iov_len = bufferSize;
            messages[i].msg_hdr.msg_iov = &vectors[i];
            messages[i].msg_hdr.msg_iovlen = 1;
            messages[i].msg_hdr.msg_name = &sources[i];
            messages[i].msg_hdr.msg_namelen = sizeof(sources[i]);
        }
        int count;
        do count = recvmmsg(readyFd, messages, maximum, MSG_DONTWAIT, NULL);
        while (count < 0 && errno == EINTR);
        if (count >= 0)
        {
            if (count > 1 && !receiveBatchObserved)
            {
                receiveBatchObserved = true;
                syslog(LOG_INFO, "recvmmsg ICMP receive batching active");
            }
            int validCount = 0;
            for (int i = 0; i < count; ++i)
            {
                ReceivedPacket packet;
                if (parseReceivedPacket(
                        i, messages[i].msg_len,
                        (const struct sockaddr *)&sources[i],
                        messages[i].msg_hdr.msg_namelen, packet) >= 0)
                    packets[validCount++] = packet;
            }
            return validCount;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == ENOSYS)
        {
            recvmmsgAvailable = false;
            syslog(LOG_WARNING, "recvmmsg unavailable; using receive fallback");
        }
        else
        {
            syslog(LOG_ERR, "error receiving ICMP packet batch: %s",
                   strerror(errno));
            return 0;
        }
    }
#endif
    Address address;
    bool reply;
    uint16_t id, seq;
    int length = receive(readyFd, address, reply, id, seq);
    if (length < 0)
        return 0;
    packets[0].address = address;
    packets[0].reply = reply;
    packets[0].id = id;
    packets[0].seq = seq;
    packets[0].length = length;
    packets[0].bufferIndex = 0;
    return 1;
}

void Echo::selectReceivedPacket(int bufferIndex)
{
#ifdef LINUX
    if (bufferIndex >= 0 && bufferIndex < MAX_BATCH_PACKETS)
        activeReceiveBuffer = bufferIndex;
#else
    (void)bufferIndex;
#endif
}

void Echo::beginBatch()
{
#ifdef LINUX
    batchActive = true;
#endif
}

void Echo::endBatch()
{
#ifdef LINUX
    flushLinuxBatch();
    batchActive = false;
#endif
}

void Echo::sendOne(int sendFd, int bufferIndex, int wireLength,
                   const Address &address)
{
#ifdef LINUX
    char *wire = &sendBuffers[bufferIndex][NETWORK_HEADER_RESERVE];
#else
    (void)bufferIndex;
    char *wire = &sendBuffer[NETWORK_HEADER_RESERVE];
#endif
    int result;
    do result = sendto(sendFd, wire, wireLength, 0,
                       address.sockaddrValue(), address.length());
    while (result < 0 && errno == EINTR);
    if (result == -1)
        syslog(LOG_ERR, "error sending icmp packet: %s", strerror(errno));
}

#ifdef LINUX
void Echo::flushLinuxBatch()
{
    int start = 0;
    while (start < pendingSendCount)
    {
        int end = start + 1;
        while (end < pendingSendCount &&
               pendingSends[end].fd == pendingSends[start].fd)
            ++end;

        int sent = 0;
        if (sendmmsgAvailable)
        {
            struct mmsghdr messages[MAX_BATCH_PACKETS];
            struct iovec vectors[MAX_BATCH_PACKETS];
            memset(messages, 0, sizeof(messages));
            memset(vectors, 0, sizeof(vectors));
            for (int i = start; i < end; ++i)
            {
                int local = i - start;
                vectors[local].iov_base =
                    &sendBuffers[i][NETWORK_HEADER_RESERVE];
                vectors[local].iov_len = pendingSends[i].wireLength;
                messages[local].msg_hdr.msg_iov = &vectors[local];
                messages[local].msg_hdr.msg_iovlen = 1;
                messages[local].msg_hdr.msg_name =
                    const_cast<struct sockaddr *>(
                        pendingSends[i].address.sockaddrValue());
                messages[local].msg_hdr.msg_namelen =
                    pendingSends[i].address.length();
            }
            while (sent < end - start)
            {
                int result = sendmmsg(pendingSends[start].fd,
                                      messages + sent,
                                      end - start - sent, 0);
                if (result > 0)
                {
                    if (result > 1 && !sendBatchObserved)
                    {
                        sendBatchObserved = true;
                        syslog(LOG_INFO, "sendmmsg ICMP send batching active");
                    }
                    sent += result;
                    continue;
                }
                if (result < 0 && errno == EINTR)
                    continue;
                if (result < 0 && errno == ENOSYS)
                {
                    sendmmsgAvailable = false;
                    syslog(LOG_WARNING,
                           "sendmmsg unavailable; using send fallback");
                }
                else if (result < 0)
                    syslog(LOG_ERR, "error sending ICMP packet batch: %s",
                           strerror(errno));
                break;
            }
        }
        for (int i = start + sent; i < end; ++i)
            sendOne(pendingSends[i].fd, i, pendingSends[i].wireLength,
                    pendingSends[i].address);
        start = end;
    }
    pendingSendCount = 0;
}
#endif

uint16_t Echo::icmpChecksum(const char *data, int length)
{
    uint16_t *data16 = (uint16_t *)data;
    uint32_t sum = 0;

    for (sum = 0; length > 1; length -= 2)
        sum += *data16++;
    if (length == 1)
        sum += *(unsigned char *)data16;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

char *Echo::sendPayloadBuffer()
{
#ifdef LINUX
    if (pendingSendCount >= MAX_BATCH_PACKETS)
        flushLinuxBatch();
    return &sendBuffers[pendingSendCount][NETWORK_HEADER_RESERVE +
                                          sizeof(EchoHeader)];
#else
    return &sendBuffer[NETWORK_HEADER_RESERVE + sizeof(EchoHeader)];
#endif
}

char *Echo::receivePayloadBuffer()
{
#ifdef LINUX
    return &receiveBuffers[activeReceiveBuffer][NETWORK_HEADER_RESERVE +
                                                sizeof(EchoHeader)];
#else
    return &receiveBuffer[NETWORK_HEADER_RESERVE + sizeof(EchoHeader)];
#endif
}
