#include "kernel_echo_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

KernelEchoGuard::KernelEchoGuard(const char *path)
    : fd(-1), originalValue(0), active(false), changed(false), users(0)
{
#ifdef __linux__
    if (path == 0)
        path = "/proc/sys/net/ipv4/icmp_echo_ignore_all";
#endif
    // Open before Server may drop privileges. Merely opening the procfs knob
    // does not change it; a credit-mode or Windows-helper session activates
    // it lazily.
    if (path != 0)
        fd = open(path, O_RDWR);
}

KernelEchoGuard::~KernelEchoGuard()
{
    if (changed)
    {
        int currentValue = -1;
        // Do not overwrite a later administrator change made while Hans was
        // running. Restore only the exact value Hans applied.
        if (readValue(currentValue) && currentValue == 1)
        {
            if (writeValue(originalValue))
                syslog(LOG_INFO, "restored kernel ICMP echo reply setting to %d",
                       originalValue);
            else
                syslog(LOG_WARNING, "could not restore kernel ICMP echo reply setting: %s",
                       strerror(errno));
        }
    }
    if (fd != -1)
        close(fd);
}

bool KernelEchoGuard::readValue(int &value)
{
    if (fd == -1 || lseek(fd, 0, SEEK_SET) == -1)
        return false;
    char buffer[16];
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
    if (length <= 0)
        return false;
    buffer[length] = '\0';
    char *end = 0;
    long parsed = strtol(buffer, &end, 10);
    if (end == buffer || (parsed != 0 && parsed != 1))
        return false;
    value = (int)parsed;
    return true;
}

bool KernelEchoGuard::writeValue(int value)
{
    if (fd == -1 || lseek(fd, 0, SEEK_SET) == -1)
        return false;
    const char *text = value == 0 ? "0\n" : "1\n";
    return write(fd, text, 2) == 2;
}

bool KernelEchoGuard::suppress()
{
    if (active)
    {
        ++users;
        return true;
    }
    if (!readValue(originalValue))
    {
        syslog(LOG_WARNING, "tunnel transport requires runtime kernel echo suppression, but it is unavailable: %s",
               fd == -1 ? "not a Linux procfs server or insufficient startup privileges" :
                          strerror(errno));
        return false;
    }
    if (originalValue != 1)
    {
        if (!writeValue(1))
        {
            syslog(LOG_WARNING, "tunnel transport requires kernel echo suppression, but it could not be enabled: %s",
                   strerror(errno));
            return false;
        }
        changed = true;
    }
    active = true;
    users = 1;
    syslog(LOG_INFO, "temporarily suppressed kernel ICMP echo replies for tunnel transport");
    return true;
}

void KernelEchoGuard::release()
{
    if (!active || users == 0)
        return;
    if (--users != 0)
        return;

    if (changed)
    {
        int currentValue = -1;
        // As in the destructor, preserve any administrator change made after
        // Hans acquired the setting.
        if (readValue(currentValue) && currentValue == 1)
        {
            if (writeValue(originalValue))
                syslog(LOG_INFO, "restored kernel ICMP echo reply setting to %d",
                       originalValue);
            else
                syslog(LOG_WARNING,
                       "could not restore kernel ICMP echo reply setting: %s",
                       strerror(errno));
        }
    }
    active = false;
    changed = false;
}
