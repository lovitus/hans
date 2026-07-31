LDFLAGS = `sh osflags ld $(MODE)`
CFLAGS = -c -g `sh osflags c $(MODE)`
CPPFLAGS = -c -g -std=c++98 -pedantic -Wall -Wextra -Wno-sign-compare -Wno-missing-field-initializers `sh osflags c $(MODE)`
TUN_DEV_FILE = `sh osflags dev $(MODE)`
GCC = gcc
GPP = g++
LWIP_CFLAGS = -Ithird_party/lwip/src/include -Ithird_party/lwip/port
LWIP_CORE_SOURCES = init def inet_chksum ip mem memp netif pbuf stats sys tcp tcp_in tcp_out timeouts udp
LWIP_IPV4_SOURCES = icmp ip4 ip4_addr ip4_frag
LWIP_OBJECTS = $(LWIP_CORE_SOURCES:%=build/lwip_%.o) $(LWIP_IPV4_SOURCES:%=build/lwip_ipv4_%.o)

.PHONY: directories test

all: directories hans

directories: build_dir

build_dir:
	mkdir -p build

tunemu.o: directories build/tunemu.o

hans: build/tun.o build/sha1.o build/main.o build/client.o build/server.o build/auth.o build/worker.o build/transport.o build/time.o build/tun_dev.o build/echo.o build/exception.o build/utility.o build/userspace.o $(LWIP_OBJECTS)
	$(GPP) -o hans build/tun.o build/sha1.o build/main.o build/client.o build/server.o build/auth.o build/worker.o build/transport.o build/time.o build/tun_dev.o build/echo.o build/exception.o build/utility.o build/userspace.o $(LWIP_OBJECTS) $(LDFLAGS)

test: build/transport_test build/userspace_test
	./build/transport_test
	./build/userspace_test

build/transport_test: directories tests/transport_test.cpp src/transport.cpp src/transport.h
	$(GPP) tests/transport_test.cpp src/transport.cpp -o $@ -g -std=c++98 -pedantic -Wall -Wextra `sh osflags c $(MODE)`

build/userspace_test: directories tests/userspace_test.cpp build/userspace.o build/utility.o build/exception.o build/time.o $(LWIP_OBJECTS)
	$(GPP) tests/userspace_test.cpp build/userspace.o build/utility.o build/exception.o build/time.o $(LWIP_OBJECTS) -o $@ -g -std=c++98 -pedantic -Wall -Wextra $(LWIP_CFLAGS) `sh osflags c $(MODE)`

build/utility.o: src/utility.cpp src/utility.h src/exception.h src/config.h
	$(GPP) -c src/utility.cpp -o $@ -o $@ $(CPPFLAGS)

build/exception.o: src/exception.cpp src/exception.h
	$(GPP) -c src/exception.cpp -o $@ $(CPPFLAGS)

build/echo.o: src/echo.cpp src/echo.h src/exception.h
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

build/auth.o: src/auth.cpp src/auth.h src/sha1.h src/utility.h
	$(GPP) -c src/auth.cpp -o $@ $(CPPFLAGS)

build/worker.o: src/worker.cpp src/worker.h src/tun.h src/exception.h src/transport.h src/time.h src/echo.h src/tun_dev.h src/config.h
	$(GPP) -c src/worker.cpp -o $@ $(CPPFLAGS)

build/transport.o: src/transport.cpp src/transport.h
	$(GPP) -c src/transport.cpp -o $@ $(CPPFLAGS)

build/time.o: src/time.cpp src/time.h
	$(GPP) -c src/time.cpp -o $@ $(CPPFLAGS)

build/userspace.o: src/userspace.cpp src/userspace.h src/exception.h src/utility.h src/time.h
	$(GPP) -c src/userspace.cpp -o $@ $(CPPFLAGS) $(LWIP_CFLAGS)

build/lwip_%.o: third_party/lwip/src/core/%.c third_party/lwip/port/lwipopts.h third_party/lwip/port/arch/cc.h
	$(GCC) -c $< -o $@ $(CFLAGS) $(LWIP_CFLAGS)

build/lwip_ipv4_%.o: third_party/lwip/src/core/ipv4/%.c third_party/lwip/port/lwipopts.h third_party/lwip/port/arch/cc.h
	$(GCC) -c $< -o $@ $(CFLAGS) $(LWIP_CFLAGS)

clean:
	rm -rf build hans

build/tunemu.o: src/tunemu.h src/tunemu.c
	$(GCC) -c src/tunemu.c -o build/tunemu.o
