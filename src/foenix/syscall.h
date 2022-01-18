
#ifndef SYSCALL_H
#define SYSCALL_H

enum {
	KERNEL_EXIT					= 0x00,
	KERNEL_CHAN_READ			= 0x10,
	KERNEL_CHAN_READ_B         	= 0x11,
	KERNEL_CHAN_WRITE			= 0x13,
	KERNEL_CHAN_WRITE_B			= 0x14,
	KERNEL_CHAN_FLUSH			= 0x15,
	KERNEL_CHAN_IOCTRL			= 0x18,
	KERNEL_OPEN					= 0x30,
	KERNEL_CLOSE				= 0x31,
	KERNEL_DELETE				= 0x37,

	FILE_MODE_READ				= 0x01,
	FILE_MODE_WRITE				= 0x02,
	FILE_MODE_CREATE_NEW		= 0x04,
	FILE_MODE_CREATE_ALWAYS		= 0x08,
	FILE_MODE_OPEN_ALWAYS		= 0x10,
	FILE_MODE_OPEN_APPEND		= 0x30,

	CON_IOCTRL_ANSI_ON			= 0x01,
	CON_IOCTRL_ANSI_OFF			= 0x02,
	CON_IOCTRL_ECHO_ON			= 0x03,
	CON_IOCTRL_ECHO_OFF			= 0x04,
};


extern int syscall(int function, ...);


void sys_exit(int result);

int sys_chan_write_b(int channel, unsigned char b);
int sys_chan_write(int channel, unsigned char * buffer, int size);

int sys_chan_read_b(int channel);
int sys_chan_read(int channel, unsigned char * buffer, int size);

int sys_chan_ioctrl(int channel, int command, unsigned char * buffer, int size);

int sys_chan_flush(int channel);

int sys_fsys_open(const char * path, int mode);
int sys_fsys_close(int fd);

int sys_fsys_delete(const char * path);

#endif