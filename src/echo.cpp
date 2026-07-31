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

#include <sys/socket.h>
#include <sys/types.h>

#ifdef WIN32
#include <w32api/windows.h>
#include <pthread.h>
#include <fcntl.h>
#include <deque>

namespace
{
    struct HansIpOptionInformation
    {
        unsigned char ttl;
        unsigned char tos;
        unsigned char flags;
        unsigned char optionsSize;
        unsigned char *optionsData;
    };

    struct HansIcmpEchoReply
    {
        DWORD address;
        DWORD status;
        DWORD roundTripTime;
        unsigned short dataSize;
        unsigned short reserved;
        void *data;
        HansIpOptionInformation options;
    };

    const DWORD HANS_IP_SUCCESS = 0;
    const int HANS_WINDOWS_MAX_PENDING = 60;
}

class Echo::WindowsBackend
{
public:
    struct Request
    {
        std::vector<char> payload;
        std::vector<char> replyBuffer;
        uint32_t realIp;
        uint16_t id;
        uint16_t seq;
        HANDLE event;
    };

    typedef HANDLE (WINAPI *CreateFileFunction)(void);
    typedef BOOL (WINAPI *CloseHandleFunction)(HANDLE);
    typedef DWORD (WINAPI *SendEchoFunction)(HANDLE, HANDLE, FARPROC, void *,
                                              DWORD, void *, unsigned short,
                                              HansIpOptionInformation *, void *,
                                              DWORD, DWORD);

    WindowsBackend(int maxPayloadSize)
        : library(NULL), icmpHandle(INVALID_HANDLE_VALUE), wakeEvent(NULL),
          stopping(false), threadStarted(false), createFileFunction(NULL),
          closeHandleFunction(NULL), sendEchoFunction(NULL)
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
        if (createFileFunction == NULL || closeHandleFunction == NULL ||
            sendEchoFunction == NULL)
            throw Exception("resolving Windows ICMP API");

        icmpHandle = createFileFunction();
        if (icmpHandle == INVALID_HANDLE_VALUE)
            throw Exception("creating Windows ICMP handle", true);
        wakeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (wakeEvent == NULL || pipe(pipeFds) != 0)
            throw Exception("creating Windows ICMP notification channel", true);
        fcntl(pipeFds[0], F_SETFL, fcntl(pipeFds[0], F_GETFL, 0) | O_NONBLOCK);
        fcntl(pipeFds[1], F_SETFL, fcntl(pipeFds[1], F_GETFL, 0) | O_NONBLOCK);
        pthread_mutex_init(&mutex, NULL);
        if (pthread_create(&thread, NULL, threadEntry, this) != 0)
            throw Exception("creating Windows ICMP worker", true);
        threadStarted = true;
        (void)maxPayloadSize;
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

        clearRequests(queued);
        clearRequests(active);
        clearRequests(completed);
        if (pipeFds[0] >= 0)
            close(pipeFds[0]);
        if (pipeFds[1] >= 0)
            close(pipeFds[1]);
        if (wakeEvent != NULL)
            CloseHandle(wakeEvent);
        if (icmpHandle != INVALID_HANDLE_VALUE && closeHandleFunction != NULL)
            closeHandleFunction(icmpHandle);
        if (library != NULL)
            FreeLibrary(library);
        pthread_mutex_destroy(&mutex);
    }

    int getFd() const
    {
        return pipeFds[0];
    }

    void send(const char *payload, int length, uint32_t realIp,
              uint16_t id, uint16_t seq)
    {
        Request *request = new Request;
        request->payload.assign(payload, payload + length);
        request->replyBuffer.resize(sizeof(HansIcmpEchoReply) + length + 32);
        request->realIp = realIp;
        request->id = id;
        request->seq = seq;
        request->event = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (request->event == NULL)
        {
            delete request;
            return;
        }
        pthread_mutex_lock(&mutex);
        queued.push_back(request);
        pthread_mutex_unlock(&mutex);
        SetEvent(wakeEvent);
    }

    bool receive(std::vector<char> &payload, uint32_t &realIp,
                 uint16_t &id, uint16_t &seq)
    {
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

        HansIcmpEchoReply *reply = reinterpret_cast<HansIcmpEchoReply *>(
            &request->replyBuffer[0]);
        bool valid = reply->status == HANS_IP_SUCCESS && reply->data != NULL;
        if (valid)
        {
            const char *data = static_cast<const char *>(reply->data);
            payload.assign(data, data + reply->dataSize);
            realIp = ntohl(reply->address);
            id = request->id;
            seq = request->seq;
        }
        CloseHandle(request->event);
        delete request;
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
        while (active.size() < HANS_WINDOWS_MAX_PENDING)
        {
            pthread_mutex_lock(&mutex);
            if (queued.empty())
            {
                pthread_mutex_unlock(&mutex);
                break;
            }
            Request *request = queued.front();
            queued.pop_front();
            pthread_mutex_unlock(&mutex);

            DWORD result = sendEchoFunction(
                icmpHandle, request->event, NULL, NULL, htonl(request->realIp),
                request->payload.empty() ? NULL : &request->payload[0],
                (unsigned short)request->payload.size(), NULL,
                &request->replyBuffer[0], (DWORD)request->replyBuffer.size(),
                2000);
            if (result > 0)
                complete(request);
            else if (GetLastError() == ERROR_IO_PENDING)
                active.push_back(request);
            else
            {
                CloseHandle(request->event);
                delete request;
            }
        }
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
        while (true)
        {
            pthread_mutex_lock(&mutex);
            bool shouldStop = stopping;
            pthread_mutex_unlock(&mutex);
            if (shouldStop)
                break;

            startQueued();
            std::vector<HANDLE> handles;
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

    HMODULE library;
    HANDLE icmpHandle;
    HANDLE wakeEvent;
    int pipeFds[2];
    pthread_t thread;
    pthread_mutex_t mutex;
    bool stopping;
    bool threadStarted;
    CreateFileFunction createFileFunction;
    CloseHandleFunction closeHandleFunction;
    SendEchoFunction sendEchoFunction;
    std::deque<Request *> queued;
    std::deque<Request *> active;
    std::deque<Request *> completed;
};
#endif
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

typedef ip IpHeader;

Echo::Echo(int maxPayloadSize, bool preferUnprivileged)
{
    datagramSocket = false;
    fd = -1;
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

    bufferSize = maxPayloadSize + headerSize();
    sendBuffer.resize(bufferSize);
    receiveBuffer.resize(bufferSize);
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
}

int Echo::headerSize()
{
    return sizeof(IpHeader) + sizeof(EchoHeader);
}

void Echo::send(int payloadLength, uint32_t realIp, bool reply, uint16_t id, uint16_t seq)
{
#ifdef WIN32
    if (windowsBackend != NULL)
    {
        if (reply)
            syslog(LOG_WARNING, "Windows ICMP helper cannot send echo replies");
        else
            windowsBackend->send(sendPayloadBuffer(), payloadLength,
                                 realIp, id, seq);
        return;
    }
#endif
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(realIp);

    if (payloadLength + sizeof(IpHeader) + sizeof(EchoHeader) > bufferSize)
        throw Exception("packet too big");

    EchoHeader *header = (EchoHeader *)(sendBuffer.data() + sizeof(IpHeader));
    header->type = reply ? 0: 8;
    header->code = 0;
    header->id = htons(id);
    header->seq = htons(seq);
    header->chksum = 0;
    header->chksum = icmpChecksum(sendBuffer.data() + sizeof(IpHeader), payloadLength + sizeof(EchoHeader));

    int result = sendto(fd, sendBuffer.data() + sizeof(IpHeader), payloadLength + sizeof(EchoHeader), 0, (struct sockaddr *)&target, sizeof(struct sockaddr_in));
    if (result == -1)
        syslog(LOG_ERR, "error sending icmp packet: %s", strerror(errno));
}

int Echo::receive(uint32_t &realIp, bool &reply, uint16_t &id, uint16_t &seq)
{
#ifdef WIN32
    if (windowsBackend != NULL)
    {
        std::vector<char> payload;
        if (!windowsBackend->receive(payload, realIp, id, seq))
            return -1;
        if (payload.size() + headerSize() > receiveBuffer.size())
            return -1;
        memcpy(receivePayloadBuffer(), &payload[0], payload.size());
        reply = true;
        return (int)payload.size();
    }
#endif
    struct sockaddr_in source;
    int source_addr_len = sizeof(struct sockaddr_in);

    char *target = receiveBuffer.data();
    int dataLength = recvfrom(fd, target, bufferSize, 0,
                              (struct sockaddr *)&source,
                              (socklen_t *)&source_addr_len);
    if (dataLength == -1)
    {
        syslog(LOG_ERR, "error receiving icmp packet: %s", strerror(errno));
        return -1;
    }

    if (datagramSocket)
    {
        bool includesIpHeader = dataLength >= (int)sizeof(IpHeader) &&
                                (((unsigned char)target[0] >> 4) == 4);
        if (!includesIpHeader)
        {
            if (dataLength + (int)sizeof(IpHeader) > bufferSize)
                return -1;
            memmove(target + sizeof(IpHeader), target, dataLength);
            memset(target, 0, sizeof(IpHeader));
            dataLength += sizeof(IpHeader);
        }
    }

    if (dataLength < sizeof(IpHeader) + sizeof(EchoHeader))
        return -1;

    EchoHeader *header = (EchoHeader *)(receiveBuffer.data() + sizeof(IpHeader));
    if ((header->type != 0 && header->type != 8) || header->code != 0)
        return -1;

    realIp = ntohl(source.sin_addr.s_addr);
    reply = header->type == 0;
    id = ntohs(header->id);
    seq = ntohs(header->seq);

    return dataLength - sizeof(IpHeader) - sizeof(EchoHeader);
}

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
    return sendBuffer.data() + headerSize();
}

char *Echo::receivePayloadBuffer()
{
    return receiveBuffer.data() + headerSize();
}
