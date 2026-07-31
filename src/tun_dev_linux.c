/*
 * Linux TUN backend with a veth/AF_PACKET fallback.
 * Derived from VTun by Maxim Krasnyansky.
 */

#include "tun_dev.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif

static int veth_fd = -1;
static char veth_public[IFNAMSIZ];
static char veth_private[IFNAMSIZ];
static int veth_private_index;
static unsigned char veth_public_mac[ETH_ALEN];

static const char *find_ip_command(void)
{
    static const char *paths[] = {
        "/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip", NULL
    };
    int i;

    for (i = 0; paths[i]; i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

static int run_ip(const char *arg1, const char *arg2, const char *arg3,
                  const char *arg4, const char *arg5, const char *arg6,
                  const char *arg7, const char *arg8)
{
    const char *ip = find_ip_command();
    pid_t child;
    int status;

    if (!ip)
    {
        errno = ENOENT;
        return -1;
    }

    child = fork();
    if (child < 0)
        return -1;
    if (child == 0)
    {
        execl(ip, ip, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
              (char *)NULL);
        _exit(127);
    }

    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int interface_exists(const char *name)
{
    return if_nametoindex(name) != 0;
}

static int choose_hans_names(char *public_name, char *private_name)
{
    int index;

    for (index = 1; index < 256; index++)
    {
        snprintf(public_name, IFNAMSIZ, "hans%d", index);
        snprintf(private_name, IFNAMSIZ, "hansp%d", index);
        if (!interface_exists(public_name) && !interface_exists(private_name))
            return 0;
    }
    errno = ENOSPC;
    return -1;
}

static int get_interface_mac(const char *name, unsigned char *mac)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
    return 0;
}

static int open_veth(char *dev)
{
    struct sockaddr_ll address;
    char public_name[IFNAMSIZ];
    char private_name[IFNAMSIZ];
    int fd;

    if (dev[0])
    {
        if (strlen(dev) >= IFNAMSIZ || interface_exists(dev))
        {
            errno = EEXIST;
            return -1;
        }
        strncpy(public_name, dev, IFNAMSIZ);
        if (choose_hans_names(veth_public, private_name) < 0)
            return -1;
    }
    else if (choose_hans_names(public_name, private_name) < 0)
        return -1;

    if (run_ip("link", "add", public_name, "type", "veth", "peer", "name",
               private_name) < 0)
        return -1;
    if (run_ip("link", "set", "dev", public_name, "up", NULL, NULL, NULL) < 0 ||
        run_ip("link", "set", "dev", public_name, "arp", "off", NULL, NULL) < 0 ||
        run_ip("link", "set", "dev", private_name, "up", NULL, NULL, NULL) < 0)
        goto failed;

    veth_private_index = if_nametoindex(private_name);
    if (!veth_private_index || get_interface_mac(public_name, veth_public_mac) < 0)
        goto failed;

    fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0)
        goto failed;

    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_IP);
    address.sll_ifindex = veth_private_index;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        close(fd);
        goto failed;
    }

    strncpy(veth_public, public_name, IFNAMSIZ);
    strncpy(veth_private, private_name, IFNAMSIZ);
    strncpy(dev, public_name, VTUN_DEV_LEN - 1);
    dev[VTUN_DEV_LEN - 1] = '\0';
    veth_fd = fd;
    return fd;

failed:
    {
        int saved_errno = errno;
        run_ip("link", "delete", public_name, NULL, NULL, NULL, NULL, NULL);
        errno = saved_errno;
    }
    return -1;
}

static int tun_open_legacy(char *dev, int istun)
{
    char tunname[32];
    int i, fd, err = 0;

    if (*dev)
    {
        snprintf(tunname, sizeof(tunname), "/dev/%s", dev);
        return open(tunname, O_RDWR);
    }

    for (i = 0; i < 255; i++)
    {
        snprintf(tunname, sizeof(tunname), "/dev/%s%d", istun ? "tun" : "tap", i);
        fd = open(tunname, O_RDWR);
        if (fd >= 0)
        {
            strncpy(dev, strrchr(tunname, '/') + 1, VTUN_DEV_LEN - 1);
            dev[VTUN_DEV_LEN - 1] = '\0';
            return fd;
        }
        if (errno != ENOENT)
            err = errno;
        else if (i)
            break;
    }
    if (err)
        errno = err;
    return -1;
}

static int tun_open_common(char *dev, int istun)
{
    int fd;
#ifdef HAVE_LINUX_IF_TUN_H
    struct ifreq ifr;
    char requested[IFNAMSIZ];

    memset(requested, 0, sizeof(requested));
    if (*dev)
        strncpy(requested, dev, IFNAMSIZ - 1);
    else if (choose_hans_names(requested, veth_private) < 0)
        return -1;

    fd = getenv("HANS_FORCE_VETH") ? -1 : open("/dev/net/tun", O_RDWR);
    if (fd >= 0)
    {
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = (istun ? IFF_TUN : IFF_TAP) | IFF_NO_PI;
        strncpy(ifr.ifr_name, requested, IFNAMSIZ - 1);
        if (ioctl(fd, TUNSETIFF, (void *)&ifr) == 0)
        {
            strncpy(dev, ifr.ifr_name, VTUN_DEV_LEN - 1);
            dev[VTUN_DEV_LEN - 1] = '\0';
            return fd;
        }
        close(fd);
    }
#endif

    if (istun)
    {
        if (!*dev)
            dev[0] = '\0';
        fd = open_veth(dev);
        if (fd >= 0)
        {
            syslog(LOG_INFO, "TUN unavailable; using veth/AF_PACKET fallback");
            return fd;
        }
    }
    return tun_open_legacy(dev, istun);
}

int tun_open(char *dev) { return tun_open_common(dev, 1); }
int tap_open(char *dev) { return tun_open_common(dev, 0); }

int tun_close(int fd, char *dev)
{
    int result = close(fd);
    (void)dev;
    if (fd == veth_fd)
    {
        run_ip("link", "delete", veth_public, NULL, NULL, NULL, NULL, NULL);
        veth_fd = -1;
        veth_public[0] = '\0';
        veth_private[0] = '\0';
    }
    return result;
}

int tap_close(int fd, char *dev) { return tun_close(fd, dev); }

int tun_write(int fd, char *buf, int len)
{
    if (fd == veth_fd)
    {
        struct sockaddr_ll address;
        memset(&address, 0, sizeof(address));
        address.sll_family = AF_PACKET;
        address.sll_protocol = htons(ETH_P_IP);
        address.sll_ifindex = veth_private_index;
        address.sll_halen = ETH_ALEN;
        memcpy(address.sll_addr, veth_public_mac, ETH_ALEN);
        return sendto(fd, buf, len, 0, (struct sockaddr *)&address, sizeof(address));
    }
    return write(fd, buf, len);
}

int tap_write(int fd, char *buf, int len) { return write(fd, buf, len); }
int tun_read(int fd, char *buf, int len) { return read(fd, buf, len); }
int tap_read(int fd, char *buf, int len) { return read(fd, buf, len); }

const char *tun_last_error(void) { return strerror(errno); }
