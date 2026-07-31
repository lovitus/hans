/* SPDX-License-Identifier: GPL-2.0 OR MIT
 *
 * Minimal declarations from the public Wintun API needed by Hans.
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 *
 * The signed wintun.dll shipped in Windows release archives is downloaded
 * unchanged from wintun.net and accompanied by its original binary license.
 */

#ifndef HANS_WINTUN_COMPAT_H
#define HANS_WINTUN_COMPAT_H

#include <w32api/windows.h>

typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;
typedef struct _TUN_SESSION *WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE(WINAPI WINTUN_CREATE_ADAPTER_FUNC)(
    LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID);
typedef WINTUN_ADAPTER_HANDLE(WINAPI WINTUN_OPEN_ADAPTER_FUNC)(LPCWSTR Name);
typedef VOID(WINAPI WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE Adapter);
typedef WINTUN_SESSION_HANDLE(WINAPI WINTUN_START_SESSION_FUNC)(
    WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
typedef VOID(WINAPI WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef HANDLE(WINAPI WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef BYTE *(WINAPI WINTUN_RECEIVE_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
typedef VOID(WINAPI WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
typedef BYTE *(WINAPI WINTUN_ALLOCATE_SEND_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
typedef VOID(WINAPI WINTUN_SEND_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session, const BYTE *Packet);

#define WINTUN_RING_CAPACITY 0x400000

#endif
