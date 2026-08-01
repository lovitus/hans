LDFLAGS = `sh osflags ld $(MODE)`
CFLAGS = -c -g `sh osflags c $(MODE)`
CPPFLAGS = -c -g -std=c++98 -pedantic -Wall -Wextra -Wno-sign-compare -Wno-missing-field-initializers `sh osflags c $(MODE)`
TUN_DEV_FILE = `sh osflags dev $(MODE)`
GCC = gcc
GPP = g++
LWIP_CFLAGS = -Ithird_party/lwip/src/include -Ithird_party/lwip/port
LWIP_HEADERS = third_party/lwip/port/lwipopts.h third_party/lwip/port/arch/cc.h
LWIP_CORE_SOURCES = init def inet_chksum ip mem memp netif pbuf stats sys tcp tcp_in tcp_out timeouts udp
LWIP_IPV4_SOURCES = icmp ip4 ip4_addr ip4_frag
LWIP_OBJECTS = $(LWIP_CORE_SOURCES:%=build/lwip_%.o) $(LWIP_IPV4_SOURCES:%=build/lwip_ipv4_%.o)

.PHONY: directories test

all: directories hans

directories: build_dir

build_dir:
	mkdir -p build

tunemu.o: directories build/tunemu.o

hans: build/tun.o build/sha1.o build/main.o build/client.o build/server.o build/auth.o build/secure.o build/monocypher.o build/worker.o build/transport.o build/time.o build/tun_dev.o build/echo.o build/exception.o build/utility.o build/userspace.o build/kernel_echo_guard.o $(LWIP_OBJECTS)
	$(GPP) -o hans build/tun.o build/sha1.o build/main.o build/client.o build/server.o build/auth.o build/secure.o build/monocypher.o build/worker.o build/transport.o build/time.o build/tun_dev.o build/echo.o build/exception.o build/utility.o build/userspace.o build/kernel_echo_guard.o $(LWIP_OBJECTS) $(LDFLAGS)

test: build/transport_test build/secure_test build/protocol_v4_test build/userspace_test build/kernel_echo_guard_test
	./build/transport_test
	./build/secure_test
	./build/protocol_v4_test
	./build/userspace_test
	./build/kernel_echo_guard_test

build/transport_test: directories tests/transport_test.cpp src/transport.cpp src/transport.h
	$(GPP) tests/transport_test.cpp src/transport.cpp -o $@ -g -std=c++98 -pedantic -Wall -Wextra `sh osflags c $(MODE)`

build/secure_test: directories tests/secure_test.cpp build/secure.o build/utility.o build/exception.o build/monocypher.o
	$(GPP) tests/secure_test.cpp build/secure.o build/utility.o build/exception.o build/monocypher.o -o $@ -g -std=c++98 -pedantic -Wall -Wextra `sh osflags c $(MODE)`

build/protocol_v4_test: directories tests/protocol_v4_test.cpp build/secure.o build/transport.o build/utility.o build/exception.o build/monocypher.o
	$(GPP) tests/protocol_v4_test.cpp build/secure.o build/transport.o build/utility.o build/exception.o build/monocypher.o -o $@ -g -std=c++98 -pedantic -Wall -Wextra `sh osflags c $(MODE)`

build/userspace_test: directories tests/userspace_test.cpp build/userspace.o build/utility.o build/exception.o build/time.o $(LWIP_OBJECTS)
	$(GPP) tests/userspace_test.cpp build/userspace.o build/utility.o build/exception.o build/time.o $(LWIP_OBJECTS) -o $@ -g -std=c++98 -pedantic -Wall -Wextra $(LWIP_CFLAGS) `sh osflags c $(MODE)`

build/kernel_echo_guard_test: directories tests/kernel_echo_guard_test.cpp build/kernel_echo_guard.o
	$(GPP) tests/kernel_echo_guard_test.cpp build/kernel_echo_guard.o -o $@ -g -std=c++98 -pedantic -Wall -Wextra `sh osflags c $(MODE)`

build/utility.o: src/utility.cpp src/utility.h src/exception.h src/config.h
	$(GPP) -c src/utility.cpp -o $@ -o $@ $(CPPFLAGS)

build/exception.o: src/exception.cpp src/exception.h
	$(GPP) -c src/exception.cpp -o $@ $(CPPFLAGS)

build/echo.o: src/echo.cpp src/echo.h src/exception.h src/config.h
	$(GPP) -c src/echo.cpp -o $@ $(CPPFLAGS)

build/tun.o: src/tun.cpp src/tun.h src/exception.h src/utility.h src/tun_dev.h
	$(GPP) -c src/tun.cpp -o $@ $(CPPFLAGS)

build/tun_dev.o: src/tun_dev.h src/wintun_compat.h
	$(GCC) -c $(TUN_DEV_FILE) -o build/tun_dev.o -o $@ $(CFLAGS)

build/sha1.o: src/sha1.cpp src/sha1.h
	$(GPP) -c src/sha1.cpp -o $@ $(CPPFLAGS)

build/main.o: src/main.cpp src/client.h src/server.h src/exception.h src/utility.h src/worker.h src/auth.h src/transport.h src/time.h src/echo.h src/tun.h src/tun_dev.h
	$(GPP) -c src/main.cpp -o $@ $(CPPFLAGS)

build/client.o: src/client.cpp src/client.h src/server.h src/exception.h src/config.h src/worker.h src/auth.h src/transport.h src/time.h src/echo.h src/tun.h src/tun_dev.h
	$(GPP) -c src/client.cpp -o $@ $(CPPFLAGS)

build/server.o: src/server.cpp src/server.h src/client.h src/utility.h src/config.h src/worker.h src/auth.h src/transport.h src/time.h src/echo.h src/tun.h src/tun_dev.h
	$(GPP) -c src/server.cpp -o $@ $(CPPFLAGS)

build/kernel_echo_guard.o: src/kernel_echo_guard.cpp src/kernel_echo_guard.h
	$(GPP) -c src/kernel_echo_guard.cpp -o $@ $(CPPFLAGS)

build/auth.o: src/auth.cpp src/auth.h src/sha1.h src/utility.h
	$(GPP) -c src/auth.cpp -o $@ $(CPPFLAGS)

build/secure.o: src/secure.cpp src/secure.h src/utility.h src/exception.h third_party/monocypher/monocypher.h
	$(GPP) -c src/secure.cpp -o $@ $(CPPFLAGS)

build/monocypher.o: third_party/monocypher/monocypher.c third_party/monocypher/monocypher.h
	$(GCC) -c third_party/monocypher/monocypher.c -o $@ $(CFLAGS)

build/worker.o: src/worker.cpp src/worker.h src/tun.h src/exception.h src/transport.h src/time.h src/echo.h src/tun_dev.h src/config.h
	$(GPP) -c src/worker.cpp -o $@ $(CPPFLAGS)

build/transport.o: src/transport.cpp src/transport.h
	$(GPP) -c src/transport.cpp -o $@ $(CPPFLAGS)

build/time.o: src/time.cpp src/time.h
	$(GPP) -c src/time.cpp -o $@ $(CPPFLAGS)

build/userspace.o: src/userspace.cpp src/userspace.h src/exception.h src/utility.h src/time.h
	$(GPP) -c src/userspace.cpp -o $@ $(CPPFLAGS) $(LWIP_CFLAGS)

$(LWIP_OBJECTS): $(LWIP_HEADERS)

build/lwip_init.o: third_party/lwip/src/core/init.c
	$(GCC) -c third_party/lwip/src/core/init.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_def.o: third_party/lwip/src/core/def.c
	$(GCC) -c third_party/lwip/src/core/def.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_inet_chksum.o: third_party/lwip/src/core/inet_chksum.c
	$(GCC) -c third_party/lwip/src/core/inet_chksum.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_ip.o: third_party/lwip/src/core/ip.c
	$(GCC) -c third_party/lwip/src/core/ip.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_mem.o: third_party/lwip/src/core/mem.c
	$(GCC) -c third_party/lwip/src/core/mem.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_memp.o: third_party/lwip/src/core/memp.c
	$(GCC) -c third_party/lwip/src/core/memp.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_netif.o: third_party/lwip/src/core/netif.c
	$(GCC) -c third_party/lwip/src/core/netif.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_pbuf.o: third_party/lwip/src/core/pbuf.c
	$(GCC) -c third_party/lwip/src/core/pbuf.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_stats.o: third_party/lwip/src/core/stats.c
	$(GCC) -c third_party/lwip/src/core/stats.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_sys.o: third_party/lwip/src/core/sys.c
	$(GCC) -c third_party/lwip/src/core/sys.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_tcp.o: third_party/lwip/src/core/tcp.c
	$(GCC) -c third_party/lwip/src/core/tcp.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_tcp_in.o: third_party/lwip/src/core/tcp_in.c
	$(GCC) -c third_party/lwip/src/core/tcp_in.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_tcp_out.o: third_party/lwip/src/core/tcp_out.c
	$(GCC) -c third_party/lwip/src/core/tcp_out.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_timeouts.o: third_party/lwip/src/core/timeouts.c
	$(GCC) -c third_party/lwip/src/core/timeouts.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_udp.o: third_party/lwip/src/core/udp.c
	$(GCC) -c third_party/lwip/src/core/udp.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_ipv4_icmp.o: third_party/lwip/src/core/ipv4/icmp.c
	$(GCC) -c third_party/lwip/src/core/ipv4/icmp.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_ipv4_ip4.o: third_party/lwip/src/core/ipv4/ip4.c
	$(GCC) -c third_party/lwip/src/core/ipv4/ip4.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_ipv4_ip4_addr.o: third_party/lwip/src/core/ipv4/ip4_addr.c
	$(GCC) -c third_party/lwip/src/core/ipv4/ip4_addr.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)
build/lwip_ipv4_ip4_frag.o: third_party/lwip/src/core/ipv4/ip4_frag.c
	$(GCC) -c third_party/lwip/src/core/ipv4/ip4_frag.c -o $@ $(CFLAGS) $(LWIP_CFLAGS)

clean:
	rm -rf build hans

build/tunemu.o: src/tunemu.h src/tunemu.c
	$(GCC) -c src/tunemu.c -o build/tunemu.o
