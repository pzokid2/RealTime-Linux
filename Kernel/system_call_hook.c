#define pr_fmt(fmt) "syscall_hook: " fmt

#include "system_call_hook.h"

MODULE_DESCRIPTION("Module hooking system call");
MODULE_AUTHOR("DaoLV <pzokid0@gmail.com>");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_err("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_err("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_err("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_err("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_err("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;
	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

static int fh_init(void)
{
	int err = 0;

 	err = init_char_device();
	if (err < 0)
	{
		pr_err("fh_init - init_char_device error: %d\n", err);
		return err;
	}
	
	err = fh_install_hooks(hook_functions, ARRAY_SIZE(hook_functions));
	if (err)
	{
		pr_err("fh_init - fh_install_hooks error: %d\n", err);
		return err;
	}

	spin_lock_init(&g_spinlock);

	pr_info("module loaded\n");
	return 0;
}

static void fh_exit(void)
{
	fh_remove_hooks(hook_functions, ARRAY_SIZE(hook_functions));
	release_char_device();
	release_msg_cache();
	pr_info("module unloaded\n");
}

module_init(fh_init);
module_exit(fh_exit);

//=============================================================================================
//                                     Char device function
//=============================================================================================

static ssize_t device_read(struct file *filp,
	char *buffer,    /* The buffer to fill with data */
	size_t length,   /* The length of the buffer     */
	loff_t *offset)  /* Our offset in the file       */
{
	int bytes_read = 0;
	struct REALTIME_INFO *msg_ptr = NULL;

	msg_ptr = get_msg_from_cache();
	if (msg_ptr == NULL)
	{
		pr_info("device_read - msg_ptr null\n");
		return 0;
	}

	bytes_read = strlen(msg_ptr->file_path) + 1;
	bytes_read += sizeof(int);

	//pr_info("device_read - copy_to_user: %d bytes\n", bytes_read);
	copy_to_user(buffer, msg_ptr, bytes_read);

	kfree(msg_ptr);
	return bytes_read;
}

static ssize_t device_write(struct file *filp,
	const char *buff,
	size_t len,
	loff_t *off)
{
	return -EINVAL;
}

static int device_open(struct inode *inode, struct file *file)
{
	if (g_device_opened)
	{
		pr_info("device_open - busy\n");
		return -EBUSY;
	}
	g_device_opened++;
	try_module_get(THIS_MODULE);
	pr_info("device_open - user connected\n");
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	release_msg_cache();
	g_device_opened--;
	module_put(THIS_MODULE);
	pr_info("device_release - user disconnected\n");
	return 0;
}

static __poll_t device_poll(struct file *filp, struct poll_table_struct *poll_table)
{
	__poll_t mask = 0;

	poll_wait(filp, &g_wait_queue_data, poll_table);

    if (g_can_read)
	{
		g_can_read = false;
        mask |= (POLLIN | POLLRDNORM);
    }

	if (g_can_write)
	{
		g_can_write = false;
		mask |= (POLLOUT | POLLWRNORM);
	}

    return mask;
}

int init_char_device(void)
{
	g_major = register_chrdev(0, (const char *)DEVICE_NAME, &g_fops); 
	if (g_major < 0)
	{
		pr_err("init_char_device - register_chrdev error: %d\n", g_major);
		return g_major;
	}

	g_char_device_class = class_create(THIS_MODULE, DEVICE_CLASS);
    if (IS_ERR(g_char_device_class))
	{
        pr_err("init_char_device - class_create error");
        unregister_chrdev(g_major, DEVICE_NAME);
		return -1;
    }
    
	g_device = device_create(g_char_device_class, NULL, MKDEV(g_major, 0), NULL, DEVICE_NAME);
	if (IS_ERR(g_device))
	{
		pr_err("init_char_device - device_create error");
		class_destroy(g_char_device_class);
		unregister_chrdev(g_major, DEVICE_NAME);
		return -1;
	}

	return 0;
}

void release_char_device(void)
{
	device_destroy(g_char_device_class, MKDEV(g_major, 0));
    class_destroy(g_char_device_class);
	unregister_chrdev(g_major, DEVICE_NAME);
}

//=============================================================================================
//                                     Util function
//=============================================================================================

void send_to_userland(void)
{
	g_can_read = true;
	wake_up_interruptible(&g_wait_queue_data);
}

void push_msg_to_cache(struct REALTIME_INFO *msg)
{
	struct REALTIME_INFO *old_msg = NULL;

	spin_lock(&g_spinlock);
	if (kfifo_is_full(&g_msg_cache))
	{
		kfifo_get(&g_msg_cache, &old_msg);
		kfree(old_msg);
	}

	kfifo_put(&g_msg_cache, msg);
	spin_unlock(&g_spinlock);
}

struct REALTIME_INFO *get_msg_from_cache(void)
{
	int ret = 0;
	struct REALTIME_INFO *msg = NULL;

	spin_lock(&g_spinlock);
	ret = kfifo_get(&g_msg_cache, &msg);
	spin_unlock(&g_spinlock);

	if (ret <= 0)
		return NULL;

	return msg;
}

void release_msg_cache(void)
{
	struct REALTIME_INFO *msg = NULL;

	spin_lock(&g_spinlock);
	while (kfifo_get(&g_msg_cache, &msg))
	{
		if (msg != NULL)
		{
			kfree(msg);
			msg = NULL;
		}
	}
	spin_unlock(&g_spinlock);
}

bool check_user_conneted(void)
{
	if (g_device_opened)
		return true;
	return false;
}

//=============================================================================================
//                                     Callback function
//=============================================================================================

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long fh_sys_write(struct pt_regs *regs)
{
	int fd = 0, pid = 0;
	fd = regs->di;
	pid = current->pid;
	process_sys_write(fd, pid);
	return real_sys_write(regs);
}
#else
static asmlinkage long fh_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
	int pid = 0;
	pid = current->pid;
	process_sys_write((int)fd, pid);
	return real_sys_write(fd, buf, count);
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long fh_sys_writev(struct pt_regs *regs)
{
	int fd = 0, pid = 0;
	fd = regs->di;
	pid = current->pid;
	process_sys_write(fd, pid);
	return real_sys_writev(regs);
}
#else
static asmlinkage long fh_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	int pid = 0;
	pid = current->pid;
	process_sys_write((int)fd, pid);
	return real_sys_writev(fd, vec, flags, vlen);
}
#endif

void process_sys_write(int fd, int pid)
{
	char *buffer = NULL;
	char *file_path = NULL;
	struct fd fd_struct = {0};
	struct file *file_struct = NULL;
    struct path *path_struct = NULL;
	struct REALTIME_INFO *msg = NULL;

	if (!check_user_conneted())
		return;

	fd_struct = fdget(fd);
	if (!fd_struct.file)
	{
		fdput(fd_struct);
		return;
	}

	file_struct = fd_struct.file;
	path_struct = &file_struct->f_path;
    path_get(path_struct);

	buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer)
		goto __RELEASE;

	file_path = d_path(path_struct, buffer, PATH_MAX);
	if (IS_ERR(file_path))
		goto __RELEASE;

	if (file_path[0] == '/')
	{
		// Test
		if (strstr(file_path, "/home/luongviet/Downloads") == NULL)
			goto __RELEASE;

		msg = kzalloc(sizeof(struct REALTIME_INFO), GFP_KERNEL);
		if (!msg)
			goto __RELEASE;
		
		msg->pid = current->pid;
		strcpy(msg->file_path, file_path);

		push_msg_to_cache(msg);
		send_to_userland();

		pr_info("sys_write() - pid: %d, file write: %s\n", current->pid, file_path);
	}

__RELEASE:
	if (buffer)
		kfree(buffer);
    path_put(path_struct);
    fdput(fd_struct);
}