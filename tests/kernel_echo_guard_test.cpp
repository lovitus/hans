#include "../src/kernel_echo_guard.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
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
    char path[128];
    snprintf(path, sizeof(path), "/tmp/hans-kernel-echo-test-%ld",
             (long)getpid());
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
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
