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
#include <ctype.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif

static int veth_fd = -1;
static char veth_public[IFNAMSIZ];
static char veth_private[IFNAMSIZ];
static int veth_private_index;
static unsigned char veth_public_mac[ETH_ALEN];
static int veth_owner_fd = -1;

#define VETH_ALIAS_PREFIX "hans.icmp-tunnel/veth/v1/"
#define VETH_TOKEN_BYTES 16
#define VETH_TOKEN_HEX_LENGTH (VETH_TOKEN_BYTES * 2)

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

static int read_text_file(const char *path, char *value, size_t value_length)
{
    int fd;
    ssize_t length;

    if (!value_length)
        return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    length = read(fd, value, value_length - 1);
    close(fd);
    if (length < 0)
        return -1;
    value[length] = '\0';
    while (length > 0 && (value[length - 1] == '\n' || value[length - 1] == '\r'))
        value[--length] = '\0';
    return 0;
}

static int read_interface_value(const char *name, const char *property,
                                char *value, size_t value_length)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/%s", name, property);
    return read_text_file(path, value, value_length);
}

static int valid_owner_alias(const char *alias, const char **token)
{
    size_t prefix_length = strlen(VETH_ALIAS_PREFIX);
    int index;

    if (strncmp(alias, VETH_ALIAS_PREFIX, prefix_length) != 0 ||
        strlen(alias + prefix_length) != VETH_TOKEN_HEX_LENGTH)
        return 0;
    for (index = 0; index < VETH_TOKEN_HEX_LENGTH; index++)
        if (!isxdigit((unsigned char)alias[prefix_length + index]))
            return 0;
    *token = alias + prefix_length;
    return 1;
}

static int bind_owner_marker(const char *token)
{
    struct sockaddr_un address;
    size_t address_length;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (fd < 0)
        return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                 "hans-veth-%s", token) >= (int)sizeof(address.sun_path) - 1)
    {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    address_length = offsetof(struct sockaddr_un, sun_path) +
                     1 + strlen(address.sun_path + 1);
    if (bind(fd, (struct sockaddr *)&address, address_length) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int create_owner_alias(char *alias, size_t alias_length)
{
    unsigned char random_bytes[VETH_TOKEN_BYTES];
    char token[VETH_TOKEN_HEX_LENGTH + 1];
    int random_fd, index;
    ssize_t length;

    random_fd = open("/dev/urandom", O_RDONLY);
    if (random_fd < 0)
        return -1;
    length = read(random_fd, random_bytes, sizeof(random_bytes));
    close(random_fd);
    if (length != (ssize_t)sizeof(random_bytes))
    {
        errno = EIO;
        return -1;
    }
    for (index = 0; index < VETH_TOKEN_BYTES; index++)
        snprintf(token + index * 2, 3, "%02x", random_bytes[index]);
    snprintf(alias, alias_length, "%s%s", VETH_ALIAS_PREFIX, token);
    return bind_owner_marker(token);
}

static int reciprocal_veth_pair(const char *public_name, const char *private_name)
{
    char public_ifindex[32], public_iflink[32];
    char private_ifindex[32], private_iflink[32];
    char public_flags[32], public_type[32], private_type[32];
    unsigned long flags;

    if (read_interface_value(public_name, "ifindex", public_ifindex,
                             sizeof(public_ifindex)) < 0 ||
        read_interface_value(public_name, "iflink", public_iflink,
                             sizeof(public_iflink)) < 0 ||
        read_interface_value(private_name, "ifindex", private_ifindex,
                             sizeof(private_ifindex)) < 0 ||
        read_interface_value(private_name, "iflink", private_iflink,
                             sizeof(private_iflink)) < 0 ||
        read_interface_value(public_name, "flags", public_flags,
                             sizeof(public_flags)) < 0 ||
        read_interface_value(public_name, "type", public_type,
                             sizeof(public_type)) < 0 ||
        read_interface_value(private_name, "type", private_type,
                             sizeof(private_type)) < 0)
        return 0;
    flags = strtoul(public_flags, NULL, 0);
    return strcmp(public_ifindex, private_iflink) == 0 &&
           strcmp(private_ifindex, public_iflink) == 0 &&
           strcmp(public_type, "1") == 0 && strcmp(private_type, "1") == 0 &&
           (flags & IFF_NOARP) != 0;
}

static void cleanup_stale_veth_pairs(void)
{
    char public_name[IFNAMSIZ], private_name[IFNAMSIZ];
    char public_alias[128], private_alias[128];
    const char *token;
    int index, owner_fd;

    for (index = 1; index < 256; index++)
    {
        snprintf(public_name, sizeof(public_name), "hans%d", index);
        snprintf(private_name, sizeof(private_name), "hansp%d", index);
        if (!interface_exists(public_name) || !interface_exists(private_name) ||
            read_interface_value(public_name, "ifalias", public_alias,
                                 sizeof(public_alias)) < 0 ||
            read_interface_value(private_name, "ifalias", private_alias,
                                 sizeof(private_alias)) < 0 ||
            strcmp(public_alias, private_alias) != 0 ||
            !valid_owner_alias(public_alias, &token) ||
            !reciprocal_veth_pair(public_name, private_name))
            continue;

        owner_fd = bind_owner_marker(token);
        if (owner_fd < 0)
            continue;

        syslog(LOG_INFO, "removing stale Hans veth pair %s/%s", public_name,
               private_name);
        run_ip("link", "delete", public_name, NULL, NULL, NULL, NULL, NULL);
        close(owner_fd);
    }
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

struct offload_setting
{
    uint32_t set_command;
    uint32_t get_command;
};

static int set_ethtool_value(int fd, const char *name, uint32_t command,
                             uint32_t value)
{
    struct ethtool_value setting;
    struct ifreq ifr;

    memset(&setting, 0, sizeof(setting));
    setting.cmd = command;
    setting.data = value;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_data = (char *)&setting;
    return ioctl(fd, SIOCETHTOOL, &ifr);
}

static int get_ethtool_value(int fd, const char *name, uint32_t command,
                             uint32_t *value)
{
    struct ethtool_value setting;
    struct ifreq ifr;

    memset(&setting, 0, sizeof(setting));
    setting.cmd = command;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_data = (char *)&setting;
    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
        return -1;
    *value = setting.data;
    return 0;
}

static int disable_veth_offloads(const char *name)
{
    static const struct offload_setting settings[] = {
        { ETHTOOL_STSO, ETHTOOL_GTSO },
#ifdef ETHTOOL_SUFO
        { ETHTOOL_SUFO, ETHTOOL_GUFO },
#endif
        { ETHTOOL_SGSO, ETHTOOL_GGSO },
        { ETHTOOL_SSG, ETHTOOL_GSG },
        { ETHTOOL_STXCSUM, ETHTOOL_GTXCSUM }
    };
    int fd, saved_errno;
    unsigned int index;
    uint32_t value;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    for (index = 0; index < sizeof(settings) / sizeof(settings[0]); index++)
    {
        if (set_ethtool_value(fd, name, settings[index].set_command, 0) < 0 &&
            errno != EOPNOTSUPP && errno != EINVAL)
            goto failed;
    }

    /* Unsupported legacy ethtool operations are acceptable only when the
     * corresponding feature cannot be queried either. If the kernel reports
     * that an offload remains enabled, AF_PACKET would receive incomplete
     * checksums or oversized GSO frames, so fail instead of creating a tunnel
     * that works for ping but silently drops TCP/UDP traffic. */
    for (index = 0; index < sizeof(settings) / sizeof(settings[0]); index++)
    {
        if (get_ethtool_value(fd, name, settings[index].get_command, &value) == 0 &&
            value != 0)
        {
            errno = EOPNOTSUPP;
            goto failed;
        }
    }

    close(fd);
    return 0;

failed:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

static int open_veth(char *dev)
{
    struct sockaddr_ll address;
    char public_name[IFNAMSIZ];
    char private_name[IFNAMSIZ];
    char owner_alias[128];
    int automatically_named = !dev[0];
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

    if (automatically_named)
    {
        veth_owner_fd = create_owner_alias(owner_alias, sizeof(owner_alias));
        if (veth_owner_fd < 0)
            return -1;
    }

    if (run_ip("link", "add", public_name, "type", "veth", "peer", "name",
               private_name) < 0)
        goto failed_without_interface;
    if (disable_veth_offloads(public_name) < 0 ||
        disable_veth_offloads(private_name) < 0 ||
        run_ip("link", "set", "dev", public_name, "up", NULL, NULL, NULL) < 0 ||
        run_ip("link", "set", "dev", public_name, "arp", "off", NULL, NULL) < 0 ||
        run_ip("link", "set", "dev", private_name, "up", NULL, NULL, NULL) < 0 ||
        (automatically_named &&
         (run_ip("link", "set", "dev", public_name, "alias", owner_alias, NULL, NULL) < 0 ||
          run_ip("link", "set", "dev", private_name, "alias", owner_alias, NULL, NULL) < 0)))
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
failed_without_interface:
    if (veth_owner_fd >= 0)
    {
        close(veth_owner_fd);
        veth_owner_fd = -1;
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

    if (istun && !*dev)
        cleanup_stale_veth_pairs();

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
        if (veth_owner_fd >= 0)
        {
            close(veth_owner_fd);
            veth_owner_fd = -1;
        }
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
