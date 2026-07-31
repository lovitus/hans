#ifndef USERSPACE_H
#define USERSPACE_H

#include <stdint.h>
#include <string>
#include <vector>
#include <sys/select.h>

struct SharePort
{
    uint16_t listenPort;
    uint32_t targetIp;
    uint16_t targetPort;
};

class UserspaceNetworkObserver
{
public:
    virtual ~UserspaceNetworkObserver() { }
    virtual void sendUserspacePacket(const char *packet, int length) = 0;
};

class UserspaceNetwork
{
public:
    UserspaceNetwork(UserspaceNetworkObserver *observer, int mtu,
                     const std::string &socksAddress,
                     const std::vector<SharePort> &sharePorts);
    ~UserspaceNetwork();

    void configure(uint32_t ip, uint32_t gateway);
    void ingest(const char *packet, int length);
    int addFileDescriptors(fd_set &readSet, fd_set &writeSet, int maxFd);
    void handleFileDescriptors(fd_set &readSet, fd_set &writeSet);
    void tick();

    static bool parseEndpoint(const std::string &text, uint32_t &ip,
                              uint16_t &port, std::string &error);
    static bool parseSharePorts(const std::string &text,
                                std::vector<SharePort> &ports,
                                std::string &error);

private:
    class Impl;
    Impl *impl;
};

#endif
