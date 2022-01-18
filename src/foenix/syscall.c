
#include "foenix/syscall.h"

void sys_exit(int result)
{
    syscall(KERNEL_EXIT, result);
}

int sys_chan_write_b(int channel, unsigned char b)
{
	return syscall(KERNEL_CHAN_WRITE_B, channel, b);
}

int sys_chan_write(int channel, unsigned char * buffer, int size)
{
	return syscall(KERNEL_CHAN_WRITE, channel, buffer, size);
}

int sys_chan_read(int channel, unsigned char * buffer, int size)
{
    return syscall(KERNEL_CHAN_READ, channel, buffer, size);
}

int sys_chan_read_b(int channel)
{
    return syscall(KERNEL_CHAN_READ_B, channel);
}

int sys_chan_ioctrl(int channel, int command, unsigned char * buffer, int size)
{
    return syscall(KERNEL_CHAN_IOCTRL, channel, command, buffer, size);
}

int sys_chan_flush(int channel)
{
    return syscall(KERNEL_CHAN_FLUSH, channel);
}


int sys_fsys_open(const char * path, int mode)
{
    return syscall(KERNEL_OPEN, path, mode);
}

int sys_fsys_close(int fd)
{
    return syscall(KERNEL_CLOSE, fd);
}

int sys_fsys_delete(const char * path)
{
    return syscall(KERNEL_DELETE, path);
}
