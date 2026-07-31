#include "../src/userspace.h"

#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    int failures = 0;

    void expect(bool condition, const char *message)
    {
        if (!condition)
        {
            std::cerr << "FAIL: " << message << std::endl;
            failures++;
        }
    }
}

int main()
{
    std::vector<SharePort> ports;
    std::string error;
    expect(UserspaceNetwork::parseSharePorts("22,80,2222=127.0.0.1:22,8080=192.168.1.20:80",
                                             ports, error),
           "valid share-port list parses");
    expect(ports.size() == 4, "all mappings are returned");
    if (ports.size() == 4)
    {
        expect(ports[0].listenPort == 22 && ports[0].targetPort == 22 &&
               ports[0].targetIp == 0x7f000001u,
               "plain port defaults to loopback and same port");
        expect(ports[2].listenPort == 2222 && ports[2].targetPort == 22 &&
               ports[2].targetIp == 0x7f000001u,
               "explicit loopback mapping parses");
        expect(ports[3].listenPort == 8080 && ports[3].targetPort == 80 &&
               ports[3].targetIp == 0xc0a80114u,
               "explicit LAN mapping parses");
    }

    expect(!UserspaceNetwork::parseSharePorts("22,22", ports, error),
           "duplicate listeners are rejected");
    expect(!UserspaceNetwork::parseSharePorts("0", ports, error),
           "port zero is rejected");
    expect(!UserspaceNetwork::parseSharePorts("80=localhost:80", ports, error),
           "mapping target must be numeric IPv4");

    uint32_t ip = 0;
    uint16_t port = 0;
    expect(UserspaceNetwork::parseEndpoint("127.0.0.1:1080", ip, port, error) &&
           ip == 0x7f000001u && port == 1080,
           "SOCKS endpoint parses");
    expect(!UserspaceNetwork::parseEndpoint("[::1]:1080", ip, port, error),
           "IPv6 listener is explicitly rejected");

    if (failures == 0)
        std::cout << "userspace tests passed" << std::endl;
    return failures == 0 ? 0 : 1;
}
