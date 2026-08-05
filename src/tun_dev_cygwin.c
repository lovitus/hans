/*
 *  Hans - IP over ICMP
 *  Copyright (C) 2013 Friedrich Schöller <hans@schoeller.se>
 *                2002-2005 Ivo Timmermans,
 *                2002-2011 Guus Sliepen <guus@tinc-vpn.org>
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

#include "tun_dev.h"
#include "wintun_compat.h"

#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#include <w32api/windows.h>
#include <w32api/winioctl.h>

#define TAP_WIN_CONTROL_CODE(request,method) CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_MAC               TAP_WIN_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_VERSION           TAP_WIN_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_MTU               TAP_WIN_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_INFO              TAP_WIN_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT TAP_WIN_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS      TAP_WIN_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      TAP_WIN_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_LOG_LINE          TAP_WIN_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   TAP_WIN_CONTROL_CODE (9, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_TUN            TAP_WIN_CONTROL_CODE (10, METHOD_BUFFERED)
#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define SYSDEVICEDIR      "\\Device\\"
#define USERDEVICEDIR     "\\DosDevices\\Global\\"
#define TAP_WIN_SUFFIX    ".tap"
#define READER_THREAD_START_MS 5000
#define READER_STARTUP_CHECK_MS 250

struct adapter_info
{
    int reader_read_fd, reader_write_fd;
    HANDLE reader_thread;
    HANDLE reader_started_event;
    HANDLE adapter_handle;
    bool use_wintun;
    HMODULE wintun_module;
    WINTUN_ADAPTER_HANDLE wintun_adapter;
    WINTUN_SESSION_HANDLE wintun_session;
    WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
    WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
    WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
    WINTUN_START_SESSION_FUNC *WintunStartSession;
    WINTUN_END_SESSION_FUNC *WintunEndSession;
    WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
    WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
    WINTUN_SEND_PACKET_FUNC *WintunSendPacket;
};

#define ERROR_BUFFER_SIZE 1024

char error_buffer[ERROR_BUFFER_SIZE];

static void error(char *format, ...)
{
    va_list vl;
    va_start(vl, format);
    vsnprintf(error_buffer, ERROR_BUFFER_SIZE, format, vl);
    va_end(vl);
}

static void noerror(void)
{
    *error_buffer = 0;
}

static const char *winerror(int err)
{
    static char buf[1024], *ptr;

    ptr = buf + sprintf(buf, "(%d) ", err);

    if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), ptr, sizeof(buf) - (ptr - buf), NULL)) {
        strcpy(ptr, "(unable to format errormessage)");
    };

    if((ptr = strchr(buf, '\r')))
        *ptr = '\0';

    return buf;
}

static struct adapter_info *get_adapter_info_from_fd(int fd)
{
    static struct adapter_info single_adapter_info = {
        .reader_read_fd = -1,
        .reader_write_fd = -1,
        .reader_thread = NULL,
        .reader_started_event = NULL,
        .adapter_handle = INVALID_HANDLE_VALUE,
        .use_wintun = false,
        .wintun_module = NULL,
        .wintun_adapter = NULL,
        .wintun_session = NULL
    };
    return &single_adapter_info;
}

static bool load_wintun_function(HMODULE module, FARPROC *target, const char *name)
{
    *target = GetProcAddress(module, name);
    if (!*target)
    {
        error("loading Wintun function %s: %s", name, winerror(GetLastError()));
        return false;
    }
    return true;
}

#define LOAD_WINTUN_FUNCTION(info, name) \
    load_wintun_function((info)->wintun_module, (FARPROC *)&(info)->name, #name)

static bool utf8_to_wide(const char *source, wchar_t *dest, int dest_length)
{
    int result = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, source, -1,
                                     dest, dest_length);
    if (!result)
        result = MultiByteToWideChar(CP_ACP, 0, source, -1, dest, dest_length);
    return result != 0;
}

static HMODULE load_wintun_module(void)
{
    wchar_t path[MAX_PATH];
    wchar_t *separator;
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);

    if (!length || length >= MAX_PATH)
        return NULL;

    separator = wcsrchr(path, L'\\');
    if (!separator || separator - path + 12 >= MAX_PATH)
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return NULL;
    }

    wcscpy(separator + 1, L"wintun.dll");
    return LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
}

static bool start_wintun_adapter(struct adapter_info *adapter_info,
                                 const char *adapter_name, char *name)
{
    wchar_t adapter_name_wide[VTUN_DEV_LEN];
    DWORD last_error;

    if (!utf8_to_wide(adapter_name, adapter_name_wide, VTUN_DEV_LEN))
        return false;

    adapter_info->wintun_adapter = adapter_info->WintunOpenAdapter(adapter_name_wide);
    if (!adapter_info->wintun_adapter)
        adapter_info->wintun_adapter = adapter_info->WintunCreateAdapter(
            adapter_name_wide, L"Hans", NULL);
    if (!adapter_info->wintun_adapter)
        return false;

    adapter_info->wintun_session = adapter_info->WintunStartSession(
        adapter_info->wintun_adapter, WINTUN_RING_CAPACITY);
    if (!adapter_info->wintun_session)
    {
        last_error = GetLastError();
        adapter_info->WintunCloseAdapter(adapter_info->wintun_adapter);
        adapter_info->wintun_adapter = NULL;
        SetLastError(last_error);
        return false;
    }

    strncpy(name, adapter_name, VTUN_DEV_LEN - 1);
    name[VTUN_DEV_LEN - 1] = '\0';
    adapter_info->use_wintun = true;
    noerror();
    return true;
}

static bool open_wintun_adapter(struct adapter_info *adapter_info, char *name)
{
    char candidate[VTUN_DEV_LEN];
    DWORD last_error = ERROR_NOT_FOUND;
    int index;

    adapter_info->wintun_module = load_wintun_module();
    if (!adapter_info->wintun_module)
    {
        error("could not open TAP adapter; loading wintun.dll fallback: %s",
              winerror(GetLastError()));
        return false;
    }

    if (!LOAD_WINTUN_FUNCTION(adapter_info, WintunCreateAdapter) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunOpenAdapter) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunCloseAdapter) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunStartSession) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunEndSession) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunGetReadWaitEvent) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunReceivePacket) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunReleaseReceivePacket) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunAllocateSendPacket) ||
        !LOAD_WINTUN_FUNCTION(adapter_info, WintunSendPacket))
        return false;

    if (name && name[0])
    {
        if (start_wintun_adapter(adapter_info, name, name))
            return true;
        error("opening or creating Wintun adapter '%s': %s", name,
              winerror(GetLastError()));
        return false;
    }

    for (index = 1; index < 256; index++)
    {
        snprintf(candidate, sizeof(candidate), "hans%d", index);
        if (start_wintun_adapter(adapter_info, candidate, name))
            return true;
        last_error = GetLastError();
    }

    error("could not find an available Wintun name from hans1 through hans255: %s",
          winerror(last_error));
    return false;
}

static HANDLE open_tap_adapter(char *name)
{
    HKEY connections_key, adapter_key;
    int adapter_index, error_code;
    char regpath[1024];
    char adapter_id[VTUN_DEV_LEN];
    char adapter_path[1024];
    char adapter_name[1024];
    HANDLE adapter_handle = INVALID_HANDLE_VALUE;
    DWORD len;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &connections_key) != ERROR_SUCCESS)
    {
        error("opening registry: %s", winerror(GetLastError()));
        return INVALID_HANDLE_VALUE;
    }

    for (adapter_index = 0; ; adapter_index++)
    {
        len = sizeof(adapter_id);
        if (RegEnumKeyEx(connections_key, adapter_index, adapter_id, &len, 0, 0, 0, NULL) != ERROR_SUCCESS)
            break;

        snprintf(regpath, sizeof(regpath), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, adapter_id);
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &adapter_key) != ERROR_SUCCESS)
            continue;
        len = sizeof(adapter_name);
        if (RegQueryValueEx(adapter_key, "Name", 0, 0, adapter_name, &len) != ERROR_SUCCESS)
        {
            RegCloseKey(adapter_key);
            continue;
        }
        RegCloseKey(adapter_key);

        if (name && name[0] && strcmp(name, adapter_name) && strcmp(name, adapter_id))
            continue;

        snprintf(adapter_path, sizeof(adapter_path), USERMODEDEVICEDIR "%s" TAP_WIN_SUFFIX, adapter_id);

        adapter_handle = CreateFile(adapter_path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
        if (adapter_handle != INVALID_HANDLE_VALUE)
            break;
    }

    RegCloseKey(connections_key);

    if (adapter_handle == INVALID_HANDLE_VALUE)
    {
        error("could not open tap adapter");
        return INVALID_HANDLE_VALUE;
    }

    strncpy(name, adapter_name, VTUN_DEV_LEN - 1);
    name[VTUN_DEV_LEN - 1] = '\0';

    noerror();
    return adapter_handle;
}

static __stdcall DWORD reader_thread(LPVOID ptr)
{
    struct adapter_info *adapter_info = ptr;
    HANDLE started_event = adapter_info->reader_started_event;
    char buf[0xffff]; // maximum IPv4 packet size
    OVERLAPPED overlapped;
    DWORD len;
    int wait_result;

    if (started_event != NULL)
        SetEvent(started_event);

    if (adapter_info->use_wintun)
    {
        DWORD read_error;
        while (true)
        {
            BYTE *packet = adapter_info->WintunReceivePacket(
                adapter_info->wintun_session, &len);
            if (packet)
            {
                if (write(adapter_info->reader_write_fd, packet, len) != (int)len)
                {
                    adapter_info->WintunReleaseReceivePacket(
                        adapter_info->wintun_session, packet);
                    syslog(LOG_ERR, "error forwarding packet from Wintun: %s",
                           strerror(errno));
                    return 1;
                }
                adapter_info->WintunReleaseReceivePacket(
                    adapter_info->wintun_session, packet);
                continue;
            }

            read_error = GetLastError();
            if (read_error == ERROR_NO_MORE_ITEMS)
            {
                wait_result = WaitForSingleObject(
                    adapter_info->WintunGetReadWaitEvent(adapter_info->wintun_session),
                    INFINITE);
                if (wait_result == WAIT_OBJECT_0)
                    continue;
            }
            else if (read_error == ERROR_HANDLE_EOF)
                return 0;

            syslog(LOG_ERR, "error reading from Wintun adapter: %s",
                   winerror(read_error));
            return 1;
        }
    }

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEvent(NULL, true, false, NULL);

    while (true)
    {
        if (!ReadFile(adapter_info->adapter_handle, buf, sizeof(buf), &len, &overlapped))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                syslog(LOG_ERR, "error reading from tap adapter: %s", winerror(GetLastError()));
                return 1;
            }

            wait_result = WaitForSingleObjectEx(overlapped.hEvent, INFINITE, false);

            if (wait_result != WAIT_OBJECT_0)
            {
                syslog(LOG_ERR, "error waiting for tap adapter: %s", winerror(GetLastError()));
                return 1;
            }

            if (!GetOverlappedResult(adapter_info->adapter_handle, &overlapped, &len, true))
            {
                syslog(LOG_ERR, "error getting tap adapter reading result: %s", winerror(GetLastError()));
                return 1;
            }
        }

        write(adapter_info->reader_write_fd, buf, len);
    }
}

static bool start_reader_thread(struct adapter_info *adapter_info)
{
    HANDLE wait_handles[2];
    DWORD wait_error = ERROR_SUCCESS;
    DWORD wait_result;

    adapter_info->reader_started_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (adapter_info->reader_started_event == NULL)
    {
        error("reader startup event creation: %s", winerror(GetLastError()));
        return false;
    }

    adapter_info->reader_thread = CreateThread(
        NULL, 0, reader_thread, adapter_info, 0, NULL);
    if (adapter_info->reader_thread == NULL)
    {
        error("reader thread creation: %s", winerror(GetLastError()));
        CloseHandle(adapter_info->reader_started_event);
        adapter_info->reader_started_event = NULL;
        return false;
    }

    /* Do not let a busy scheduler consume the health-check grace period
     * before the reader has run at all. */
    wait_handles[0] = adapter_info->reader_thread;
    wait_handles[1] = adapter_info->reader_started_event;
    wait_result = WaitForMultipleObjects(2, wait_handles, FALSE,
                                         READER_THREAD_START_MS);
    if (wait_result != WAIT_OBJECT_0 + 1)
    {
        if (wait_result == WAIT_FAILED)
            wait_error = GetLastError();
        if (wait_result != WAIT_OBJECT_0)
            TerminateThread(adapter_info->reader_thread, 1);
        CloseHandle(adapter_info->reader_thread);
        adapter_info->reader_thread = NULL;
        CloseHandle(adapter_info->reader_started_event);
        adapter_info->reader_started_event = NULL;

        if (wait_result == WAIT_OBJECT_0)
            error("adapter reader stopped before startup");
        else if (wait_result == WAIT_TIMEOUT)
            error("adapter reader did not start within %d ms",
                  READER_THREAD_START_MS);
        else
            error("waiting for adapter reader startup: %s",
                  winerror(wait_error));
        return false;
    }

    CloseHandle(adapter_info->reader_started_event);
    adapter_info->reader_started_event = NULL;

    /* A TAP device can remain registered and accept CreateFile() even when
     * its driver can no longer service overlapped reads.  Give the first read
     * enough time to enter its normal pending state; an early thread exit is
     * a data-plane failure, not a usable adapter. */
    wait_result = WaitForSingleObject(adapter_info->reader_thread,
                                      READER_STARTUP_CHECK_MS);
    if (wait_result == WAIT_TIMEOUT)
        return true;

    if (wait_result != WAIT_OBJECT_0)
    {
        wait_error = GetLastError();
        TerminateThread(adapter_info->reader_thread, 1);
    }
    CloseHandle(adapter_info->reader_thread);
    adapter_info->reader_thread = NULL;

    if (wait_result == WAIT_OBJECT_0)
        error("adapter reader stopped during startup");
    else
        error("waiting for adapter reader startup: %s",
              winerror(wait_error));
    return false;
}

int tun_open(char *dev)
{
    struct adapter_info *adapter_info;
    int socket_pair[2];
    char requested_name[VTUN_DEV_LEN];
    bool explicit_name = dev && dev[0];

    requested_name[0] = '\0';
    if (explicit_name)
    {
        strncpy(requested_name, dev, sizeof(requested_name) - 1);
        requested_name[sizeof(requested_name) - 1] = '\0';
    }

    /* The protocol argument must be zero for AF_UNIX. Older Cygwin releases
     * tolerated PF_UNIX here, while current releases correctly reject it
     * with EPROTONOSUPPORT before the TAP adapter is opened. */
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socket_pair))
    {
        error("creating socket pair: %s", strerror(errno));
        return -1;
    }

    adapter_info = get_adapter_info_from_fd(socket_pair[0]);
    adapter_info->reader_read_fd = socket_pair[0];
    adapter_info->reader_write_fd = socket_pair[1];

    adapter_info->adapter_handle = open_tap_adapter(dev);
    if (adapter_info->adapter_handle == INVALID_HANDLE_VALUE)
    {
        if (!open_wintun_adapter(adapter_info, dev) ||
            !start_reader_thread(adapter_info))
        {
            tun_close(adapter_info->reader_read_fd, NULL);
            return -1;
        }
        return adapter_info->reader_read_fd;
    }

    if (start_reader_thread(adapter_info))
        return adapter_info->reader_read_fd;

    syslog(LOG_WARNING,
           "TAP adapter '%s' failed its startup read check; falling back to Wintun",
           dev);
    CloseHandle(adapter_info->adapter_handle);
    adapter_info->adapter_handle = INVALID_HANDLE_VALUE;

    /* Auto-selection must not reuse the broken TAP display name.  Let Wintun
     * select the first free hansN name.  An explicit -d remains explicit. */
    if (explicit_name)
    {
        strncpy(dev, requested_name, VTUN_DEV_LEN - 1);
        dev[VTUN_DEV_LEN - 1] = '\0';
    }
    else
        dev[0] = '\0';

    if (!open_wintun_adapter(adapter_info, dev) ||
        !start_reader_thread(adapter_info))
    {
        tun_close(adapter_info->reader_read_fd, NULL);
        return -1;
    }

    return adapter_info->reader_read_fd;
}

int tun_close(int fd, char *dev)
{
    struct adapter_info *adapter_info = get_adapter_info_from_fd(fd);

    if (adapter_info->reader_thread != NULL)
    {
        TerminateThread(adapter_info->reader_thread, 0);
        CloseHandle(adapter_info->reader_thread);
        adapter_info->reader_thread = NULL;
    }

    if (adapter_info->reader_started_event != NULL)
    {
        CloseHandle(adapter_info->reader_started_event);
        adapter_info->reader_started_event = NULL;
    }

    close(adapter_info->reader_read_fd);
    adapter_info->reader_read_fd = -1;

    close(adapter_info->reader_write_fd);
    adapter_info->reader_write_fd = -1;

    if (adapter_info->adapter_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(adapter_info->adapter_handle);
        adapter_info->adapter_handle = INVALID_HANDLE_VALUE;
    }

    if (adapter_info->wintun_session)
    {
        adapter_info->WintunEndSession(adapter_info->wintun_session);
        adapter_info->wintun_session = NULL;
    }

    if (adapter_info->wintun_adapter)
    {
        adapter_info->WintunCloseAdapter(adapter_info->wintun_adapter);
        adapter_info->wintun_adapter = NULL;
    }

    if (adapter_info->wintun_module)
    {
        FreeLibrary(adapter_info->wintun_module);
        adapter_info->wintun_module = NULL;
    }

    adapter_info->use_wintun = false;

    return 0;
}

int tun_write(int fd, char *buf, int len)
{
    struct adapter_info *adapter_info = get_adapter_info_from_fd(fd);
    OVERLAPPED overlapped;
    DWORD written;

    if (adapter_info->use_wintun)
    {
        BYTE *packet = adapter_info->WintunAllocateSendPacket(
            adapter_info->wintun_session, len);
        if (!packet)
        {
            error("allocating Wintun send packet: %s", winerror(GetLastError()));
            return -1;
        }
        memcpy(packet, buf, len);
        adapter_info->WintunSendPacket(adapter_info->wintun_session, packet);
        noerror();
        return len;
    }

    memset(&overlapped, 0, sizeof(overlapped));

    if (!WriteFile(adapter_info->adapter_handle, buf, len, &written, &overlapped))
    {
        error("tap write: %s", winerror(GetLastError()));
        return -1;
    }

    return written;
}

int tun_read(int fd, char *buf, int len)
{
    len = read(fd, buf, len);
    if (len == -1)
        error("reader read: %s", strerror(errno));
    return len;
}

const char *tun_last_error()
{
    return error_buffer;
}

bool tun_set_ip(int fd, uint32_t local, uint32_t network, uint32_t netmask)
{
    struct adapter_info *adapter_info = get_adapter_info_from_fd(fd);
    uint32_t addresses[3];
    DWORD status;
    DWORD len;

    /* Wintun is configured through netsh in Tun::setIp(). The TAP-specific
     * control requests below do not apply to its layer-3 ring interface. */
    if (adapter_info->use_wintun)
    {
        noerror();
        return true;
    }

    addresses[0] = htonl(local);
    addresses[1] = htonl(network);
    addresses[2] = htonl(netmask);

    if (!DeviceIoControl(adapter_info->adapter_handle, TAP_WIN_IOCTL_CONFIG_TUN,
        &addresses, sizeof(addresses), &addresses, sizeof(addresses), &len, NULL))
    {
        error("configuring tap addresses: %s", winerror(GetLastError()));
        return false;
    }

    status = true;
    if (!DeviceIoControl(adapter_info->adapter_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
        &status, sizeof(status), &status, sizeof(status), &len, NULL))
    {
        error("enabling tap device: %s", winerror(GetLastError()));
        return false;
    }

    noerror();
    return true;
}
