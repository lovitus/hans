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

#define MAX_BUFFERED_PACKETS 20
// Adaptive v3 credits can briefly lag a new TCP burst while the window grows.
// Keep that transient burst instead of applying the much smaller legacy cap.
#define MAX_V3_BUFFERED_PACKETS 256

#define KEEP_ALIVE_INTERVAL (60 * 1000)
#define POLL_INTERVAL 2000

// Credit requests are deliberately held by the server until tunnel data is
// available.  A refresh has to overlap the lifetime of an outstanding
// Windows IP Helper request; otherwise the server can reply to an echo token
// that IcmpSendEcho2 has already expired.
#define CREDIT_REFRESH_MS 5000
#define WINDOWS_ICMP_REQUEST_TIMEOUT_MS 6000
#define WINDOWS_ICMP_MAX_PENDING 60
// Keep two complete adaptive windows live during the refresh overlap.
#define WINDOWS_ICMP_MAX_CREDITS (WINDOWS_ICMP_MAX_PENDING / 2)

#define CHALLENGE_SIZE 20

#define DEVICE_ID_HEX_SIZE 32

// #define DEBUG_ONLY(a) a
#define DEBUG_ONLY(a)
