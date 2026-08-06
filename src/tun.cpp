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

#include "tun.h"
#include "exception.h"
#include "utility.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sstream>

#ifdef LINUX
#include <errno.h>
#include <poll.h>
#endif

#ifdef WIN32
#include <w32api/windows.h>
#endif

typedef ip IpHeader;

using std::string;

#ifdef WIN32
static bool winsystem(char *cmd)
{
    STARTUPINFO info = { sizeof(info) };
    PROCESS_INFORMATION processInfo;
    DWORD exitCode = 1;
    if (CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
    {
        WaitForSingleObject(processInfo.hProcess, INFINITE);
        GetExitCodeProcess(processInfo.hProcess, &exitCode);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }
    return exitCode == 0;
}
#endif

Tun::Tun(const string *device, int mtu, bool enabled)
{
    this->mtu = mtu;
    this->enabled = enabled;
    this->fd = -1;

    if (!enabled)
        return;

    if (device)
        this->device = *device;

    this->device.resize(VTUN_DEV_LEN);
    fd = tun_open(&this->device[0]);
    this->device.resize(strlen(this->device.data()));

    if (fd == -1)
        throw Exception(string("could not create tunnel device: ") + tun_last_error());

    syslog(LOG_INFO, "opened tunnel device: %s", this->device.data());

    setMtu(mtu);
}

void Tun::setMtu(int newMtu)
{
    mtu = newMtu;
    if (!enabled)
        return;
    std::stringstream cmdline;
#ifdef WIN32
    cmdline << "netsh interface ipv4 set subinterface \"" << this->device
            << "\" mtu=" << mtu;
    if (!winsystem(cmdline.str().data()))
        syslog(LOG_ERR, "could not set tun device mtu");
#else
    cmdline << "/sbin/ifconfig " << this->device << " mtu " << mtu;
    if (system(cmdline.str().data()) != 0)
        syslog(LOG_ERR, "could not set tun device mtu");
#endif
}

Tun::~Tun()
{
    if (enabled)
        tun_close(fd, &device[0]);
}

void Tun::setIp(uint32_t ip, uint32_t destIp)
{
    if (!enabled)
        return;
    std::stringstream cmdline;
    string ips = Utility::formatIp(ip);
    string destIps = Utility::formatIp(destIp);

#ifdef WIN32
    cmdline << "netsh interface ip set address name=\"" << device << "\" "
            << "static " << ips << " 255.255.255.0";
    if (!winsystem(cmdline.str().data()))
        syslog(LOG_ERR, "could not set tun device ip address on interface \"%s\" "
               "(netsh failed; the address may already be assigned to another adapter)",
               device.data());

    if (!tun_set_ip(fd, ip, ip & 0xffffff00, 0xffffff00))
        syslog(LOG_ERR, "could not set tun device driver ip address: %s", tun_last_error());
#elif LINUX
    cmdline << "/sbin/ifconfig " << device << " " << ips << " netmask 255.255.255.0";
    if (system(cmdline.str().data()) != 0)
        syslog(LOG_ERR, "could not set tun device ip address");
#else
    cmdline << "/sbin/ifconfig " << device << " " << ips << " " << destIps
            << " netmask 255.255.255.255";
    if (system(cmdline.str().data()) != 0)
        syslog(LOG_ERR, "could not set tun device ip address");
#endif
}

void Tun::write(const char *buffer, int length)
{
    if (!enabled)
        return;
    if (tun_write(fd, (char *)buffer, length) == -1)
        syslog(LOG_ERR, "error writing %d bytes to tun: %s", length, tun_last_error());
}

int Tun::read(char *buffer)
{
    if (!enabled)
        return -1;
    int length = tun_read(fd, buffer, mtu);
    if (length == -1)
        syslog(LOG_ERR, "error reading from tun: %s", tun_last_error());
    return length;
}

int Tun::read(char *buffer, uint32_t &sourceIp, uint32_t &destIp)
{
    int length = read(buffer);

    // A host may automatically attach an IPv6 link-local address to a TUN
    // interface. Hans carries IPv4 inner packets only; never reinterpret an
    // IPv6 or truncated packet as an IPv4 source/destination tuple.
    if (length < (int)sizeof(IpHeader) ||
        (((const unsigned char *)buffer)[0] >> 4) != 4)
        return -1;

    IpHeader *header = (IpHeader *)buffer;
    int headerLength = header->ip_hl * 4;
    if (headerLength < (int)sizeof(IpHeader) || headerLength > length)
        return -1;
    sourceIp = ntohl(header->ip_src.s_addr);
    destIp = ntohl(header->ip_dst.s_addr);

    return length;
}

bool Tun::hasPendingRead() const
{
#ifdef LINUX
    if (!enabled || fd < 0)
        return false;
    struct pollfd descriptor;
    descriptor.fd = fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    int result;
    do result = poll(&descriptor, 1, 0);
    while (result < 0 && errno == EINTR);
    return result > 0 && (descriptor.revents & POLLIN) != 0;
#else
    return false;
#endif
}
