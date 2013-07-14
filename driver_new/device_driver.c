/*
 *  SWAP device driver
 *  modules/driver_new/device_driver.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) Samsung Electronics, 2013
 *
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP device driver implement
 *
 */

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/err.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/splice.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <asm/uaccess.h>

#include <ksyms/ksyms.h>

#include "device_driver.h"
#include "swap_driver_errors.h"
#include "driver_to_buffer.h"
#include "swap_ioctl.h"
#include "driver_defs.h"
#include "device_driver_to_driver_to_buffer.h"
#include "driver_to_buffer.h"
#include "driver_to_msg.h"

#define SWAP_DEVICE_NAME "swap_device"

/* swap_device driver routines */
static int swap_device_open(struct inode *inode, struct file *filp);
static int swap_device_release(struct inode *inode, struct file *file);
static ssize_t swap_device_read(struct file *filp, char __user *buf,
								size_t count, loff_t *f_pos);
static ssize_t swap_device_write(struct file *filp, const char __user *buf,
								 size_t count, loff_t *f_pos);
static long swap_device_ioctl(struct file *filp, unsigned int cmd,
							 unsigned long arg);
static ssize_t swap_device_splice_read(struct file *filp, loff_t *ppos,
									   struct pipe_inode_info *pipe, size_t len,
									   unsigned int flags);

/* File operations structure */
const struct file_operations swap_device_fops = {
	.read = swap_device_read,
	.write = swap_device_write,
	.open = swap_device_open,
	.release = swap_device_release,
	.unlocked_ioctl = swap_device_ioctl,
	.splice_read = swap_device_splice_read,
};

/* Typedefs for splice_* funcs. Prototypes are for linux-3.8.6 */
typedef ssize_t(*splice_to_pipe_p_t)(struct pipe_inode_info *pipe,
					 struct splice_pipe_desc *spd);
typedef int(*splice_grow_spd_p_t)(const struct pipe_inode_info *pipe,
					struct splice_pipe_desc *spd);

static splice_to_pipe_p_t splice_to_pipe_p = NULL;
static splice_grow_spd_p_t splice_grow_spd_p = NULL;

static msg_handler_t msg_handler = NULL;

/* Device numbers */
static dev_t swap_device_no = 0;

/* Device cdev struct */
static struct cdev *swap_device_cdev = NULL;

/* Device class struct */
static struct class *swap_device_class = NULL;

/* Device device struct */
static struct device *swap_device_device = NULL;

/* Reading tasks queue */
static DECLARE_WAIT_QUEUE_HEAD(swap_device_wait);

/* We need this realization of splice_shrink_spd() because of the its desing
 * frequent changes that I have encountered in custom kernels */
void swap_device_splice_shrink_spd(struct pipe_inode_info *pipe,
                                   struct splice_pipe_desc *spd)
{
	if (pipe->buffers <= PIPE_DEF_BUFFERS)
		return;

	kfree(spd->pages);
	kfree(spd->partial);
}


/* Register device TODO Think of permanent major */
int swap_device_init(void)
{
	int result;

	/* Allocating device major and minor nums for swap_device */
	result = alloc_chrdev_region(&swap_device_no, 0, 1, SWAP_DEVICE_NAME);
	if (result < 0) {
		print_crit("Major number allocation has failed\n");
		result = -E_SD_ALLOC_CHRDEV_FAIL;
		goto init_fail;
	}

	/* Creating device class. Using IS_ERR, because class_create returns ERR_PTR
	 * on error. */
	swap_device_class = class_create(THIS_MODULE, SWAP_DEVICE_NAME);
	if (IS_ERR(swap_device_class)) {
		print_crit("Class creation has failed\n");
		result = -E_SD_CLASS_CREATE_FAIL;
		goto init_fail;
	}

	/* Cdev allocation */
	swap_device_cdev = cdev_alloc();
	if (!swap_device_cdev) {
		print_crit("Cdev structure allocation has failed\n");
		result = -E_SD_CDEV_ALLOC_FAIL;
		goto init_fail;
	}

	/* Cdev intialization and setting file operations */
	cdev_init(swap_device_cdev, &swap_device_fops);

	/* Adding cdev to system */
	result = cdev_add(swap_device_cdev, swap_device_no, 1);
	if (result < 0) {
		print_crit("Device adding has failed\n");
		result = -E_SD_CDEV_ADD_FAIL;
		goto init_fail;
	}

	/* Create device struct */
	swap_device_device = device_create(swap_device_class, NULL, swap_device_no,
									   "%s", SWAP_DEVICE_NAME);
	if (IS_ERR(swap_device_device)) {
		print_crit("Device struct creating has failed\n");
		result = -E_SD_DEVICE_CREATE_FAIL;
		goto init_fail;
	}

	/* Find splice_* funcs addresses */
	splice_to_pipe_p = (splice_to_pipe_p_t)swap_ksyms("splice_to_pipe");
	if (!splice_to_pipe_p) {
		print_err("splice_to_pipe() not found!\n");
		result = -E_SD_NO_SPLICE_FUNCS;
		goto init_fail;
	}

	splice_grow_spd_p = (splice_grow_spd_p_t)swap_ksyms("splice_grow_spd");
	if (!splice_grow_spd_p) {
		print_err("splice_grow_spd() not found!\n");
		result = -E_SD_NO_SPLICE_FUNCS;
		goto init_fail;
	}

	return 0;

init_fail:
	if (swap_device_cdev) {
		cdev_del(swap_device_cdev);
	}
	if (swap_device_class) {
		class_destroy(swap_device_class);
	}
	if (swap_device_no) {
		unregister_chrdev_region(swap_device_no, 1);
	}
	return result;
}

/* Unregister device TODO Check wether driver is registered */
void swap_device_exit(void)
{
	splice_to_pipe_p = NULL;
	splice_grow_spd_p = NULL;

	device_destroy(swap_device_class, swap_device_no);
	cdev_del(swap_device_cdev);
	class_destroy(swap_device_class);
	unregister_chrdev_region(swap_device_no, 1);
}

static int swap_device_open(struct inode *inode, struct file *filp)
{
	// TODO MOD_INC_USE_COUNT
	return 0;
}

static int swap_device_release(struct inode *inode, struct file *filp)
{
	// TODO MOD_DEC_USE_COUNT
	return 0;
}

static ssize_t swap_device_read(struct file *filp, char __user *buf,
								size_t count, loff_t *f_pos)
{
	/* Wait queue item that consists current task. It is used to be added in
	 * swap_device_wait queue if there is no data to be read. */
	DEFINE_WAIT(wait);
	int result;

	//TODO : Think about spin_locks to prevent reading race condition.
	while((result = driver_to_buffer_next_buffer_to_read()) != E_SD_SUCCESS) {

		/* Add process to the swap_device_wait queue and set the current task
		 * state TASK_INTERRUPTIBLE. If there is any data to be read, then the
		 * current task is removed from the swap_device_wait queue and its state
		 * is changed to this. */
		prepare_to_wait(&swap_device_wait, &wait, TASK_INTERRUPTIBLE);

		if (result < 0) {
			result = 0;
			goto swap_device_read_error;
		} else if (result == E_SD_NO_DATA_TO_READ) {
			/* Yes, E_SD_NO_DATA_TO_READ should be positive, cause it's not
			 * really an error */
			if (filp->f_flags & O_NONBLOCK) {
				result = -EAGAIN;
				goto swap_device_read_error;
			}
			if (signal_pending(current)) {
				result = -ERESTARTSYS;
				goto swap_device_read_error;
			}
			schedule();
			finish_wait(&swap_device_wait, &wait);
		}
	}

	result = driver_to_buffer_read(buf, count);
	/* If there is an error - return 0 */
	if (result < 0)
		result = 0;


	return result;

swap_device_read_error:
	finish_wait(&swap_device_wait, &wait);

	return result;
}

static ssize_t swap_device_write(struct file *filp, const char __user *buf,
								 size_t count, loff_t *f_pos)
{
	char *kern_buffer = NULL;
	ssize_t result = 0;

	kern_buffer = kmalloc(count, GFP_KERNEL);
	if (!kern_buffer) {
		print_err("Error allocating memory for buffer\n");
		goto swap_device_write_out;
	}

	result = copy_from_user(kern_buffer, buf, count);

	result = count - result;

	/* Return 0 if there was an error while writing */
	result = driver_to_buffer_write(result, kern_buffer);
	if (result < 0)
		result = 0;

	kfree(kern_buffer);

swap_device_write_out:
	return result;
}

static long swap_device_ioctl(struct file *filp, unsigned int cmd,
							 unsigned long arg)
{
	int result;

	switch(cmd) {
		case SWAP_DRIVER_BUFFER_INITIALIZE:
		{
			struct buffer_initialize initialize_struct;

			result = copy_from_user(&initialize_struct, (void*)arg,
									sizeof(struct buffer_initialize));
			if (result) {
				break;
			}

			result = driver_to_buffer_initialize(initialize_struct.size,
												 initialize_struct.count);
			if (result < 0) {
				print_err("Buffer initialization failed %d\n", result);
				break;
			}
			result = E_SD_SUCCESS;

			break;
		}
		case SWAP_DRIVER_BUFFER_UNINITIALIZE:
		{
			result = driver_to_buffer_uninitialize();
			if (result < 0)
			print_err("Buffer uninitialization failed %d\n", result);

			break;
		}
		case SWAP_DRIVER_NEXT_BUFFER_TO_READ:
		{
			/* Use this carefully */
			result = driver_to_buffer_next_buffer_to_read();
			if (result == E_SD_NO_DATA_TO_READ) {
				/* TODO Do what we usually do when there are no subbuffers to
				 * read (make daemon sleep ?) */
			}
			break;
		}
		case SWAP_DRIVER_FLUSH_BUFFER:
		{
			result = driver_to_buffer_flush();
			break;
		}
		case SWAP_DRIVER_MSG:
			if (msg_handler) {
				result = msg_handler((void __user *)arg);
			} else {
				print_warn("msg_handler() is not register\n");
				result = -EINVAL;
			}
			break;
		default:
			print_warn("Unknown command %d\n", cmd);
			result = -EINVAL;
			break;

	}
	return result;
}

static void swap_device_pipe_buf_release(struct pipe_inode_info *inode,
										 struct pipe_buffer *pipe)
{
	__free_page(pipe->page);
}

static void swap_device_page_release(struct splice_pipe_desc *spd,
									 unsigned int i)
{
	__free_page(spd->pages[i]);
}

static const struct pipe_buf_operations swap_device_pipe_buf_ops = {
	.can_merge = 0,
	.map = generic_pipe_buf_map,
	.unmap = generic_pipe_buf_unmap,
	.confirm = generic_pipe_buf_confirm,
	.release = swap_device_pipe_buf_release,
	.steal = generic_pipe_buf_steal,
	.get = generic_pipe_buf_get
};

static ssize_t swap_device_splice_read(struct file *filp, loff_t *ppos,
									   struct pipe_inode_info *pipe,
									   size_t len, unsigned int flags)
{
	/* Wait queue item that consists current task. It is used to be added in
	 * swap_device_wait queue if there is no data to be read. */
	DEFINE_WAIT(wait);

	int result;
	struct page *pages[PIPE_DEF_BUFFERS];
	struct partial_page partial[PIPE_DEF_BUFFERS];
	struct splice_pipe_desc spd = {
		.pages = pages,
		.partial = partial,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 5))
		.nr_pages_max = PIPE_DEF_BUFFERS,
#endif
		.nr_pages = 0,
		.flags = flags,
		.ops = &swap_device_pipe_buf_ops,
		.spd_release = swap_device_page_release,
	};

	/* Get next buffer to read */
	//TODO : Think about spin_locks to prevent reading race condition.
	while((result = driver_to_buffer_next_buffer_to_read()) != E_SD_SUCCESS) {

		/* Add process to the swap_device_wait queue and set the current task
		 * state TASK_INTERRUPTIBLE. If there is any data to be read, then the
		 * current task is removed from the swap_device_wait queue and its state
		 * is changed. */
		prepare_to_wait(&swap_device_wait, &wait, TASK_INTERRUPTIBLE);
		if (result < 0) {
			print_err("driver_to_buffer_next_buffer_to_read error %d\n", result);
			//TODO Error return to OS
			result = 0;
			goto swap_device_splice_read_error;
		} else if (result == E_SD_NO_DATA_TO_READ) {
			if (filp->f_flags & O_NONBLOCK) {
				result = -EAGAIN;
				goto swap_device_splice_read_error;
			}
			if (signal_pending(current)) {
				result = -ERESTARTSYS;
				goto swap_device_splice_read_error;
			}
			schedule();
			finish_wait(&swap_device_wait, &wait);
		}
	}

	if (splice_grow_spd_p(pipe, &spd)) {
		result = -ENOMEM;
		goto swap_device_splice_read_out;
	}

	result = driver_to_buffer_fill_spd(&spd);
	if (result != 0) {
		print_err("Cannot fill spd for splice\n");
		goto swap_device_shrink_spd;
	}

	result = splice_to_pipe_p(pipe, &spd);

swap_device_shrink_spd:
	swap_device_splice_shrink_spd(pipe, &spd);

swap_device_splice_read_out:
	return result;

swap_device_splice_read_error:
	finish_wait(&swap_device_wait, &wait);

	return result;
}

void swap_device_wake_up_process(void)
{
	wake_up_interruptible(&swap_device_wait);
}

void set_msg_handler(msg_handler_t mh)
{
	msg_handler = mh;
}
EXPORT_SYMBOL_GPL(set_msg_handler);
