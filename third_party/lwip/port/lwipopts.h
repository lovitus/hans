#ifndef HANS_LWIPOPTS_H
#define HANS_LWIPOPTS_H

/* Hans drives lwIP from its existing select() loop. */
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_TIMERS                     1

#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_ARP                        0
#define LWIP_ETHERNET                   0
#define LWIP_ICMP                       1
#define LWIP_RAW                        0
#define LWIP_UDP                        1
#define LWIP_TCP                        1
#define LWIP_DNS                        0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_IGMP                       0

#define LWIP_NETIF_API                  0
#define LWIP_SOCKET                     0
#define LWIP_NETCONN                    0
#define LWIP_STATS                      0
#define LWIP_CHECKSUM_CTRL_PER_NETIF    0
#define LWIP_NETIF_HOSTNAME             0
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_NETIF_LINK_CALLBACK        0
#define LWIP_NETIF_REMOVE_CALLBACK      0

#define MEM_ALIGNMENT                   8
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEMP_NUM_PBUF                   512
#define MEMP_NUM_RAW_PCB                4
#define MEMP_NUM_UDP_PCB                64
#define MEMP_NUM_TCP_PCB                128
#define MEMP_NUM_TCP_PCB_LISTEN         64
#define MEMP_NUM_TCP_SEG                4096
#define MEMP_NUM_SYS_TIMEOUT            16
#define PBUF_POOL_SIZE                  1024
#define PBUF_POOL_BUFSIZE               1600

#define TCP_MSS                         1400
/* Keep enough data in flight on higher-BDP VPN paths. These are upper bounds,
 * not per-connection preallocations: lwIP allocates pbufs on demand. Separate
 * overridable values also let validation builds isolate memory/performance
 * tradeoffs without source edits. */
#ifndef HANS_TCP_RX_WINDOW
#define HANS_TCP_RX_WINDOW              (8 * 1024 * 1024)
#endif
#ifndef HANS_TCP_TX_WINDOW
#define HANS_TCP_TX_WINDOW              (6 * 1024 * 1024)
#endif
#ifndef HANS_TCP_SEND_QUEUE_LENGTH
#define HANS_TCP_SEND_QUEUE_LENGTH      12288
#endif
#define TCP_WND                         HANS_TCP_RX_WINDOW
#define TCP_SND_BUF                     HANS_TCP_TX_WINDOW
#define TCP_SND_QUEUELEN                HANS_TCP_SEND_QUEUE_LENGTH
#define TCP_SNDLOWAT                    8192
#define TCP_QUEUE_OOSEQ                 1
#define LWIP_TCP_SACK_OUT               1
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   8
#define TCP_LISTEN_BACKLOG              1
#define LWIP_TCP_KEEPALIVE              1
#define LWIP_NETIF_TX_SINGLE_PBUF       0

/* Use a finer TCP timer so isolated loss is recovered without waiting for
 * lwIP's default 500 ms slow tick. Keep an independent RTO floor: a one-tick
 * (100 ms) timeout is too aggressive on normal Internet paths with jitter. */
#ifndef HANS_TCP_TIMER_INTERVAL_MS
#define HANS_TCP_TIMER_INTERVAL_MS      50
#endif
#ifndef HANS_TCP_MIN_RTO_MS
#define HANS_TCP_MIN_RTO_MS             400
#endif
#define TCP_TMR_INTERVAL                HANS_TCP_TIMER_INTERVAL_MS
#define HANS_TCP_MIN_RTO_TICKS          \
    ((HANS_TCP_MIN_RTO_MS + (2 * TCP_TMR_INTERVAL) - 1) / \
     (2 * TCP_TMR_INTERVAL))
#define HANS_TCP_CLAMP_RTO_TICKS(ticks) \
    ((s16_t)LWIP_MAX(HANS_TCP_MIN_RTO_TICKS, (ticks)))

/* One port-zero listener is an on-demand fallback for Hans --allports. */
#define HANS_TCP_WILDCARD_LISTENER      1

#define IP_REASSEMBLY                   1
#define IP_FRAG                         1
#define IP_REASS_MAX_PBUFS              64
#define IP_DEFAULT_TTL                  64
#define LWIP_CHKSUM_ALGORITHM           2

#endif
