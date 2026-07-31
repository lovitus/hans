#ifndef HANS_LWIP_ARCH_CC_H
#define HANS_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#ifndef BYTE_ORDER
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif

#define LWIP_RAND() hans_lwip_rand()
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#ifdef __cplusplus
extern "C" {
#endif
uint32_t hans_lwip_rand(void);
#ifdef __cplusplus
}
#endif

#define LWIP_PLATFORM_DIAG(x) do { fprintf(stderr, x); } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { \
    fprintf(stderr, "lwIP assertion failed: %s (%s:%d)\n", \
            (x), __FILE__, __LINE__); abort(); \
} while (0)

#endif
