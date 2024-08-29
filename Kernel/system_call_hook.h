#pragma once

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/poll.h>
#include <linux/kfifo.h>
#include <linux/spinlock.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#include <linux/proc_fs.h>
#endif

#define USE_FENTRY_OFFSET 0

#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#else
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define DEVICE_NAME							"daolv@1999"
#define DEVICE_CLASS						"cdc_daolv@1999"
#define FIFO_SIZE							1024

#define HOOK(_name, _function, _original)   \
	{					                    \
		.name = SYSCALL_NAME(_name),	    \
		.function = (_function),	        \
		.original = (_original),	        \
	}

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_write)(struct pt_regs *regs);
static asmlinkage long fh_sys_write(struct pt_regs *regs);

static asmlinkage long (*real_sys_writev)(struct pt_regs *regs);
static asmlinkage long fh_sys_writev(struct pt_regs *regs);

// static asmlinkage long (*real_sys_pwritev)(struct pt_regs *regs);
// static asmlinkage long fh_sys_pwritev(struct pt_regs *regs);

// static asmlinkage long (*real_sys_pwritev2)(struct pt_regs *regs);
// static asmlinkage long fh_sys_pwritev2(struct pt_regs *regs);

// static asmlinkage long (*real_sys_pwrite64)(struct pt_regs *regs);
// static asmlinkage long fh_sys_pwrite64(struct pt_regs *regs);
#else
static asmlinkage long (*real_sys_write)(unsigned int fd, const char __user *buf, size_t count);
static asmlinkage long fh_sys_write(unsigned int fd, const char __user *buf, size_t count);

static asmlinkage long (*real_sys_writev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
static asmlinkage long fh_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);

// static asmlinkage long (*real_sys_pwritev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
// static asmlinkage long fh_sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);

// static asmlinkage long (*real_sys_pwritev2)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
// static asmlinkage long fh_sys_pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);

// static asmlinkage long (*real_sys_pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
// static asmlinkage long fh_sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
#endif

static struct ftrace_hook hook_functions[] = {
	HOOK("sys_write",  fh_sys_write,  &real_sys_write),
	HOOK("sys_writev", fh_sys_writev, &real_sys_writev),
	// HOOK("sys_pwritev", fh_sys_pwritev, &real_sys_pwritev),
	// HOOK("sys_pwritev2", fh_sys_pwritev2, &real_sys_pwritev2),
	// HOOK("sys_pwrite64", fh_sys_pwrite64, &real_sys_pwrite64),
};

static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static __poll_t device_poll(struct file *, struct poll_table_struct *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops g_fops = {
	.proc_read		= device_read,
	.proc_write		= device_write,
	.proc_open		= device_open,
	.proc_release	= device_release,
	.proc_poll		= device_poll,
};
#else
static struct file_operations g_fops = {
    .read 		= device_read,
    .write 		= device_write,
	.open 		= device_open,
    .release 	= device_release,
	.poll 		= device_poll,
};
#endif

struct REALTIME_INFO
{
	int pid;
	char file_path[PATH_MAX];
};

void send_to_userland(void);
int init_char_device(void);
void release_char_device(void);
void push_msg_to_cache(struct REALTIME_INFO *);
struct REALTIME_INFO *get_msg_from_cache(void);
void release_msg_cache(void);
void process_sys_write(int, int);
bool check_user_connected(void);

unsigned int g_major = 0;
static int g_device_opened = 0;
static struct class *g_char_device_class;
static struct device *g_device;
static bool g_can_write = false;
static bool g_can_read = false;
static DECLARE_WAIT_QUEUE_HEAD(g_wait_queue_data);
static DECLARE_KFIFO(g_msg_cache, struct REALTIME_INFO*, FIFO_SIZE);
static spinlock_t g_spinlock;