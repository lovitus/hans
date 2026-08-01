#ifndef KERNEL_ECHO_GUARD_H
#define KERNEL_ECHO_GUARD_H

class KernelEchoGuard
{
public:
    explicit KernelEchoGuard(const char *path = 0);
    ~KernelEchoGuard();

    bool suppress();
    void release();

private:
    bool readValue(int &value);
    bool writeValue(int value);

    int fd;
    int originalValue;
    bool active;
    bool changed;
    unsigned int users;
};

#endif
