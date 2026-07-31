#include "../src/kernel_echo_guard.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int readValue(const char *path)
{
    int fd = open(path, O_RDONLY);
    assert(fd != -1);
    char value = 0;
    assert(read(fd, &value, 1) == 1);
    close(fd);
    return value - '0';
}

int main()
{
    char path[] = "/tmp/hans-kernel-echo-test-XXXXXX";
    int fd = mkstemp(path);
    assert(fd != -1);
    assert(write(fd, "0\n", 2) == 2);
    close(fd);

    {
        KernelEchoGuard guard(path);
        assert(guard.suppress());
        assert(readValue(path) == 1);
        assert(guard.suppress());
    }
    assert(readValue(path) == 0);
    unlink(path);
    return 0;
}
