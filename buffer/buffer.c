#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "buffer.h"

#define BUF_DEBUG

#ifdef BUF_DEBUG
#define DPRINTF(format, args...) \
	do { \
		char *f = strrchr(__FILE__, '/'); \
		printk("%s[%s:%u:%s]: " format "\n", BUF_DEVICE, f ? f + 1: __FILE__, \
				__LINE__, __FUNCTION__, ##args); \
	} while (0)
#else /* !BUF_DEBUG */
#define DPRINTF(format, args...)
#endif /* BUF_DEBUG */

#define EPRINTF(format, args...) \
	do { \
		printk("%s: " format "\n", BUF_DEVICE, ##args); \
	} while (0)

struct chunk {
	struct list_head list;
	unsigned long size;
	void *payload;
};

struct buffer_device {
	struct list_head free_chunks;
	struct list_head used_chunks;
	spinlock_t lock;
	struct cdev cdev;
	dev_t dev;
	unsigned long size;
	unsigned long chunk_size;
	char *buf;
};

static int buf_open(struct inode *, struct file *);
static int buf_release(struct inode *, struct file *);
static int buf_mmap(struct file *, struct vm_area_struct *);
static ssize_t buf_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t buf_write(struct file *, const char __user *, size_t, loff_t *);
static long buf_ioctl(struct file *, unsigned int, unsigned long);
static unsigned int buf_poll(struct file *, struct poll_table_struct *);
static ssize_t buf_splice_read(struct file *, loff_t *,
		struct pipe_inode_info *, size_t, unsigned int);
static ssize_t buf_splice_write(struct pipe_inode_info *, struct file *,
		loff_t *, size_t, unsigned int);

static struct file_operations buf_fops = {
	.owner = THIS_MODULE,
	.open = buf_open,
	.release = buf_release,
	.mmap = buf_mmap,
	.read = buf_read,
	.write = buf_write,
	.unlocked_ioctl = buf_ioctl,
	.poll = buf_poll,
	.splice_read = buf_splice_read,
	.splice_write = buf_splice_write
};

static struct buffer_device bdevice = {
	.free_chunks = LIST_HEAD_INIT(bdevice.free_chunks),
	.used_chunks = LIST_HEAD_INIT(bdevice.used_chunks),
	.lock = __SPIN_LOCK_UNLOCKED(bdevice.lock),
	.dev = MKDEV(BUF_DEFAULT_MAJOR, BUF_DEFAULT_MAJOR),
	.size = 0,
	.chunk_size = 0,
	.buf = NULL
};

/* --- chunks manipulation routines --- */
static inline void *buf_get_free_chunk(void)
{
	if (!list_empty(&bdevice.free_chunks))
		return list_first_entry(&bdevice.free_chunks, struct chunk, list);

	return NULL;
}

static inline void *buf_get_used_chunk(void)
{
	if (!list_empty(&bdevice.used_chunks))
		return list_first_entry(&bdevice.used_chunks, struct chunk, list);

	return NULL;
}

static inline void buf_free_chunk(struct chunk *chunk)
{
	list_move_tail(&chunk->list, &bdevice.free_chunks);
	chunk->size = 0;
}

static inline void buf_use_chunk(struct chunk *chunk)
{
	list_move_tail(&chunk->list, &bdevice.used_chunks);
	chunk->size = 0;
}

static inline void buf_check_chunk_size(struct chunk *chunk, unsigned long size)
{
	return (bdevice.chunk_size - chunk->size <= size);
}

static inline unsigned long buf_copy_to_chunk(struct chunk *chunk,
		const char __user *buf, size_t length)
{
	return copy_from_user(chunk->payload, buf, length);
}

static inline unsigned long buf_copy_from_chunk(struct chunk *chunk,
		char __user *buf, size_t length)
{
	return copy_to_user(buf, chunk->payload, length);
}

/* --- buffer manipulation routines */
static inline void *buf_get_chunk(int i)
{
	return (((struct chunk *)bdevice.buf) + i); //TODO FIXME!!!!
}

static int buf_init(unsigned long size, unsigned long chunk_size)
{
	int retval = 0;

	INIT_LIST_HEAD(&bdevice.free_chunks);
	INIT_LIST_HEAD(&bdevice.used_chunks);
	bdevice.size = 0;
	bdevice.chunk_size = 0;

	bdevice.buf = vmalloc(size);
	if (!bdevice.buf) {
		retval = -ENOMEM;
		goto out;
	}

	/*for (;;) { //TODO
		struct chunk *chunk = buf_get_chunk(i); //TODO
		list_add_tail(&chunk->list, &bdevice.free_chunks);
	}*/

out:
	return retval;
}

static int buf_free(void)
{
	INIT_LIST_HEAD(&bdevice.free_chunks);
	INIT_LIST_HEAD(&bdevice.used_chunks);
	bdevice.size = 0;
	bdevice.chunk_size = 0;

	if (bdevice.buf)
		vfree(bdevice.buf);
	bdevice.buf = NULL;

	return 0;
}

/* --- char dev file operations --- */
static int buf_open(struct inode *inode, struct file *filp)
{
	/*struct buffer_device *dev = NULL; //TODO

	if (filp->f_flags & O_WRONLY) {
	}

	if ((filp->f_flags & O_ACCMODE) == O_WRONLY) {
	}

	if (!atomic_dec_and_test()) {
		//TODO
		return -EBUSY;
	}

	filp->private_data = dev;*/
	DPRINTF("");
	return 0;
}

static int buf_release(struct inode *inode, struct file *filp)
{
	DPRINTF("");
	return 0;
}

static int buf_mmap(struct file *filp, struct vm_area_struct *vma)
{
	EPRINTF("mmap() operation is not supported");
	return -ENODEV;
}

static ssize_t buf_read(struct file *filp, char __user *buf, size_t length,
		loff_t *offset)
{
	DPRINTF("");
	return 0;
}

static ssize_t buf_write(struct file *filp, const char __user *buf,
		size_t length, loff_t *offset)
{
	DPRINTF("");
	return length;
}

static long buf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	DPRINTF("");
	return 0;
}

static unsigned int buf_poll(struct file *filp, struct poll_table_struct *table)
{
	DPRINTF("");
	return 0;
}

static ssize_t buf_splice_read(struct file *filp, loff_t *offset,
		struct pipe_inode_info *pipe, size_t length, unsigned int flags)
{
	DPRINTF("");
	return 0;
}

static ssize_t buf_splice_write(struct pipe_inode_info *pipe, struct file *filp,
		loff_t *offset, size_t length, unsigned int flags)
{
	DPRINTF("");
	return 0;
}

/* --- module init/exit routines --- */
static int __init buf_module_init(void)
{
	int retval = 0;

	bdevice.dev = MKDEV(BUF_DEFAULT_MAJOR, BUF_DEFAULT_MINOR);

	retval = alloc_chrdev_region(&bdevice.dev, BUF_DEFAULT_MINOR,
			BUF_NUM_DEVICES, BUF_DEVICE);
	if (retval < 0) {
		EPRINTF("(%d) - alloc_chrdev_region", retval);
		goto out;
	}

	cdev_init(&bdevice.cdev, &buf_fops);
	bdevice.cdev.owner = THIS_MODULE;
	bdevice.cdev.ops = &buf_fops;

	retval = cdev_add(&bdevice.cdev, bdevice.dev, BUF_NUM_DEVICES);
	if (retval < 0) {
		EPRINTF("(%d) - cdev_add", retval);
		goto out;
	}

out:
	DPRINTF("major = %d", MAJOR(bdevice.dev));
	return retval;
}

static void __exit buf_module_exit(void)
{
	DPRINTF("major = %d", MAJOR(bdevice.dev));
	cdev_del(&bdevice.cdev);
	unregister_chrdev_region(bdevice.dev, BUF_NUM_DEVICES);
}

module_init(buf_module_init);
module_exit(buf_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP buffer module");
