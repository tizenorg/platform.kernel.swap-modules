/*
 *  SWAP Buffer Module
 *  modules/buffer/swap_buffer_module.c
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP Buffer implement
 *
 */

/* SWAP Buffer interface implementation */

#include "swap_buffer_module.h"
#include "buffer_queue.h"
#include "buffer_description.h"
#include "swap_buffer_errors.h"
#include "kernel_operations.h"

/* Bitwise mask for buffer status */
enum _swap_buffer_status_mask {
	BUFFER_FREE = 0,
	BUFFER_ALLOC = 1,
	BUFFER_PAUSE = 2,
	BUFFER_WORK = 4
};

/* Buffer status masks:
 *   0 - memory free
 *   1 - memory allocated
 *  10 - buffer overflow
 * 100 - buffer work
 * */
static unsigned char swap_buffer_status = BUFFER_FREE;

/* Callback type */
typedef int(*subbuffer_callback_type)(void);

/* Callback that is called when full subbuffer appears */
static subbuffer_callback_type subbuffer_callback = NULL;

/* One subbuffer size */
static size_t subbuffers_size = 0;

/* Subbuffers count */
static unsigned int subbuffers_num = 0;

static unsigned int enough_writable_bufs = 0;
static unsigned int min_writable_bufs = 0;
static int (*low_mem_cb)(void) = NULL;
static int (*enough_mem_cb)(void) = NULL;


static inline int areas_overlap(const void *area1,const void *area2, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		if ((area1 + i == area2) || (area1 + i == area2))
			return 1;

	return 0;
}

static inline unsigned int percent_to_count(unsigned char percent,
					     unsigned int cnt)
{
	return (percent * cnt) / 100;
}

int swap_buffer_init(struct buffer_init_t *buf_init)
{
	int result = -1;

	swap_buffer_status &= ~BUFFER_WORK;
	print_debug("status buffer stop = %d\n", swap_buffer_status);

	if ((buf_init->top_threshold > 100) || (buf_init->lower_threshold > 100) ||
	    (buf_init->top_threshold < buf_init->lower_threshold))
		return -E_SB_WRONG_THRESHOLD;

	min_writable_bufs = percent_to_count(buf_init->lower_threshold,
					     buf_init->nr_subbuffers);

	enough_writable_bufs = percent_to_count(buf_init->top_threshold,
						buf_init->nr_subbuffers);

	low_mem_cb = buf_init->low_mem_cb;
	enough_mem_cb = buf_init->enough_mem_cb;

	if ((swap_buffer_status & BUFFER_ALLOC) &&
		(subbuffers_size == buf_init->subbuffer_size) &&
		(subbuffers_num == buf_init->nr_subbuffers) &&
		((subbuffer_callback_type)subbuffer_callback ==
				  buf_init->subbuffer_full_cb)) {
		result = buffer_queue_reset();
		goto swap_buffer_init_work;
	}

	subbuffer_callback = buf_init->subbuffer_full_cb;
	subbuffers_size = buf_init->subbuffer_size;
	subbuffers_num = buf_init->nr_subbuffers;

	result = buffer_queue_allocation(subbuffers_size, subbuffers_num);
	if (result < 0)
		return result;

	result = get_pages_count_in_subbuffer();

	swap_buffer_status |= BUFFER_ALLOC;
	print_debug("status buffer alloc = %d\n", swap_buffer_status);

swap_buffer_init_work:
	swap_buffer_status |= BUFFER_WORK;
	print_debug("status buffer work = %d\n", swap_buffer_status);

	return result;
}
EXPORT_SYMBOL_GPL(swap_buffer_init);


int swap_buffer_uninit(void)
{
	/* Check whether buffer is allocated */
	if (!(swap_buffer_status & BUFFER_ALLOC))
		return -E_SB_NOT_ALLOC;

	/* Stop buffer */
	swap_buffer_status &= ~BUFFER_WORK;
	print_debug("status buffer stop = %d\n", swap_buffer_status);

	/* Check whether all buffers are released */
	if (get_busy_buffers_count())
		return -E_SB_UNRELEASED_BUFFERS;

	/* Free */
	buffer_queue_free();

	subbuffer_callback = NULL;
	subbuffers_size = 0;
	subbuffers_num = 0;
	min_writable_bufs = 0;
	enough_writable_bufs = 0;
	low_mem_cb = NULL;
	enough_mem_cb = NULL;

	swap_buffer_status &= ~BUFFER_ALLOC;
	print_debug("status buffer dealloc = %d\n", swap_buffer_status);

	return E_SB_SUCCESS;
}
EXPORT_SYMBOL_GPL(swap_buffer_uninit);


ssize_t swap_buffer_write(void *data, size_t size)
{
	int result = E_SB_SUCCESS;
	struct swap_subbuffer *buffer_to_write = NULL;
	void *ptr_to_write = NULL;

	/* Size sanitization */
	if ((size > subbuffers_size) || (size == 0))
		return -E_SB_WRONG_DATA_SIZE;

	/* Check buffer status */
	if (!(swap_buffer_status & BUFFER_WORK))
		return -E_SB_IS_STOPPED;

	/* Get next write buffer and occupying semaphore */
	buffer_to_write = get_from_write_list(size, &ptr_to_write);
	if (!buffer_to_write)
		return -E_SB_NO_WRITABLE_BUFFERS;

	/* Check for overlapping */
	if (areas_overlap(ptr_to_write, data, size)) {
		result = -E_SB_OVERLAP;
		goto buf_write_sem_post;
	}

	/* Copy data to buffer */
	/* XXX Think of using memmove instead - useless, anyway overlapping means
	 * that something went wrong. */
	memcpy(ptr_to_write, data, size);

	result = size;

	/* Unlock sync (Locked in get_from_write_list()) */
buf_write_sem_post:
	sync_unlock(&buffer_to_write->buffer_sync);

	return result;
}
EXPORT_SYMBOL_GPL(swap_buffer_write);


int swap_buffer_get(struct swap_subbuffer **subbuffer)
{
	int result = 0;
	struct swap_subbuffer *buffer_to_read = NULL;

	/* Check buffer status */
	if (!(swap_buffer_status & BUFFER_WORK))
		return -E_SB_IS_STOPPED;

	/* Get next read buffer */
	buffer_to_read = get_from_read_list();
	if (!buffer_to_read)
		return -E_SB_NO_READABLE_BUFFERS;

	/* Add to busy list */
	buffer_to_read->next_in_queue = NULL;
	add_to_busy_list(buffer_to_read);

	*subbuffer = buffer_to_read;

	result = get_pages_count_in_subbuffer();

	return result;
}
EXPORT_SYMBOL_GPL(swap_buffer_get);


int swap_buffer_release(struct swap_subbuffer **subbuffer)
{
	int result;

	/* Remove from busy list (includes sanitization) */
	result = remove_from_busy_list(*subbuffer);
	if (result < 0)
		return result;

	/* Add to write list */
	add_to_write_list(*subbuffer);

	return E_SB_SUCCESS;
}
EXPORT_SYMBOL_GPL(swap_buffer_release);


int swap_buffer_flush(void)
{
	int result = 0;

	/* Set all non-empty write buffers to read list */
	buffer_queue_flush();

	/* Get count of all full buffers */
	result = get_full_buffers_count();

	return result;
}
EXPORT_SYMBOL_GPL(swap_buffer_flush);


int swap_buffer_callback(void *buffer)
{
	int result;

	if (!subbuffer_callback) {
		return -E_SB_NO_CALLBACK;
	}

	result = subbuffer_callback();
	if (result < 0)
		print_err("Callback error! Error code: %d\n", result);

	return result;
}

static int __init swap_buffer_module_init(void)
{
	printk(KERN_NOTICE "SWAP_BUFFER : Buffer module initialized\n");
	return E_SB_SUCCESS;
}

static void __exit swap_buffer_module_exit(void)
{
	if (swap_buffer_status & BUFFER_ALLOC)
		swap_buffer_uninit();
	printk(KERN_NOTICE "SWAP_BUFFER : Buffer module unintialized\n");
}

module_init(swap_buffer_module_init);
module_exit(swap_buffer_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP buffer module");
MODULE_AUTHOR("Aksenov A.S.");
