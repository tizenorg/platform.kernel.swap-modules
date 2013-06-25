/*
 *  SWAP Buffer Module
 *  modules/buffer/buffer_queue.c
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

/* SWAP buffer queues implementation */

/* For all memory allocation/deallocation operations, except buffer memory
 * allocation/deallocation should be used 
 *  memory_allocation(size_t memory_size)
 *  memory_free(void *ptr)
 * defines.
 * For subbuffer allocation/deallocation operations should be used
 *  buffer_allocation(size_t subbuffer_size)
 *  buffer_free(void *ptr, size_t subbuffer_size)
 * To get buffer pointer for any usage, EXCEPT ALLOCATION AND DEALLOCATION
 * use the following define:
 *  buffer_pointer(void *ptr_to_buffer_element_of_swap_buffer_structure)
 * DO NOT USE SUBBUFFER PTR IN STRUCT SWAP_BUFFER WITHOUT THIS DEFINE!
 * It will be ok for user space, but fail in kernel space.
 *
 * See space_dep_types_and_def.h for details */



#include "buffer_queue.h"
#include "swap_buffer_to_buffer_queue.h"
#include "swap_buffer_errors.h"

/* Queue structure. Consist of pointers to the first and the last elements of
 * queue. */
struct queue {
	struct swap_subbuffer *start_ptr;
	struct swap_subbuffer *end_ptr;
	struct sync_t queue_sync;
};

/* Write queue */
struct queue write_queue = {
	.start_ptr = NULL,
	.end_ptr = NULL,
	.queue_sync = {
		.flags = 0x0
	}
};

/* Read queue */
struct queue read_queue = {
	.start_ptr = NULL,
	.end_ptr = NULL,
	.queue_sync = {
		.flags = 0x0
	}
};

/* Pointers array. Points to busy buffers */
static struct swap_subbuffer **queue_busy = NULL;

/* Store last busy element */
static unsigned int queue_busy_last_element;

/* Subbuffers count */
static unsigned int queue_subbuffer_count = 0;

/* One subbuffer size */
static size_t queue_subbuffer_size = 0;

/* Busy list sync */
static struct sync_t buffer_busy_sync = {
	.flags = 0x0
};

/* Memory pages count in one subbuffer */
static int pages_order_in_subbuffer = 0;


int buffer_queue_allocation(size_t subbuffer_size,
			    unsigned int subbuffers_count)
{
	unsigned int i = 0;
	unsigned int j = 0;
	unsigned int allocated_buffers = 0;
	unsigned int allocated_structs = 0;
	struct swap_subbuffer *clean_tmp_struct;
	int result;

	/* Static varibles initialization */
	queue_subbuffer_size = subbuffer_size;
	queue_subbuffer_count = subbuffers_count;
	queue_busy_last_element = 0;

	/* Set variable pages_in_subbuffer. It is used for allocation and
	 * deallocation memory pages and its value is returned from
	 * swap_buffer_get() and contains page count in one subbuffer.
	 * All this useful only in kernel space. In userspace it is dummy.*/
	set_pages_order_in_subbuffer(queue_subbuffer_size);
	/* Sync primitives initialization */
	sync_init(&read_queue.queue_sync);
	sync_init(&write_queue.queue_sync);
	sync_init(&buffer_busy_sync);

	/* Memory allocation for queue_busy */
	queue_busy = memory_allocation(sizeof(&queue_busy) * queue_subbuffer_count);

	if (!queue_busy) {
		result = E_SB_NO_MEM_QUEUE_BUSY;
		goto buffer_allocation_error_ret;
	}

	/* Memory allocation for swap_subbuffer structures */

	/* Allocation for first structure. */
	write_queue.start_ptr = memory_allocation(sizeof(&write_queue.start_ptr));

	if (!write_queue.start_ptr) {
		result = E_SB_NO_MEM_BUFFER_STRUCT;
		goto buffer_allocation_queue_busy_free;
	}
	allocated_structs++;


	write_queue.end_ptr = write_queue.start_ptr;

	write_queue.end_ptr->next_in_queue = NULL;
	write_queue.end_ptr->full_buffer_part = 0;
	write_queue.end_ptr->data_buffer = buffer_allocation(queue_subbuffer_size);
	if (!write_queue.end_ptr->data_buffer) {
		print_err("Cannot allocate memory for buffer 1\n");
		result = E_SB_NO_MEM_DATA_BUFFER;
		goto buffer_allocation_error_free;
	}
	allocated_buffers++;

	print_msg(" Buffer allocated = 0x%x\n", (unsigned long)write_queue.end_ptr->data_buffer);

	sync_init(&write_queue.end_ptr->buffer_sync);

	/* Buffer initialization */
	memset(buffer_address(write_queue.end_ptr->data_buffer), 0, queue_subbuffer_size);

	/* Allocation for other structures. */
	for (i = 1; i < queue_subbuffer_count; i++) {
		write_queue.end_ptr->next_in_queue =
		    memory_allocation(sizeof(write_queue.end_ptr->next_in_queue));
		if (!write_queue.end_ptr->next_in_queue) {
			result = E_SB_NO_MEM_BUFFER_STRUCT;
			goto buffer_allocation_error_free;
		}
		allocated_structs++;

		/* Now next write_queue.end_ptr is next */
		write_queue.end_ptr = write_queue.end_ptr->next_in_queue;

		write_queue.end_ptr->next_in_queue = NULL;
		write_queue.end_ptr->full_buffer_part = 0;
		write_queue.end_ptr->data_buffer = 
			buffer_allocation(queue_subbuffer_size);
		if (!write_queue.end_ptr->data_buffer) {
			result = E_SB_NO_MEM_DATA_BUFFER;
			goto buffer_allocation_error_free;
		}
		allocated_buffers++;

		print_msg(" Buffer allocated = 0x%x, pages_order = %d\n", 
			  (unsigned long)buffer_address(write_queue.end_ptr->data_buffer), 
			  pages_order_in_subbuffer);

		sync_init(&write_queue.end_ptr->buffer_sync);

		/* Buffer initialization */
		memset(buffer_address(write_queue.end_ptr->data_buffer), 0,
		       queue_subbuffer_size);
	}

	return E_SB_SUCCESS;

	/* In case of errors, this code is called */
	/* Free all previously allocated memory */
buffer_allocation_error_free:
	clean_tmp_struct = write_queue.start_ptr;

	for (j = 0; j < allocated_structs; j++) {
		clean_tmp_struct = write_queue.start_ptr;
		if (allocated_buffers) {
			buffer_free(clean_tmp_struct->data_buffer, queue_subbuffer_size);
			allocated_buffers--;
		}
		if (write_queue.start_ptr != write_queue.end_ptr)
			write_queue.start_ptr = write_queue.start_ptr->next_in_queue;
		memory_free(clean_tmp_struct);
	}
	write_queue.end_ptr = NULL;
	write_queue.start_ptr = NULL;

buffer_allocation_queue_busy_free:
	memory_free(queue_busy);
	queue_busy = NULL;

buffer_allocation_error_ret:
	return result;
}

void buffer_queue_free(void)
{
	struct swap_subbuffer *tmp = NULL;

	//TODO Lock read list semaphore to prevent getting subbuffer from read list 
	/* Set all write buffers to read list */
	set_all_to_read_list();

	/* Free buffers and structures memory that are in read list */
	while (read_queue.start_ptr) {
		tmp = read_queue.start_ptr;
		read_queue.start_ptr = read_queue.start_ptr->next_in_queue;
		buffer_free(tmp->data_buffer, queue_subbuffer_size);
		print_msg(" Buffer free = 0x%x\n", (unsigned long)
			   buffer_address(tmp->data_buffer));
		memory_free(tmp);
	}

	/* Free busy_list */
	memory_free(queue_busy);
	queue_busy = NULL;

	queue_subbuffer_size = 0;
	queue_subbuffer_count = 0;
	read_queue.start_ptr = NULL;
	read_queue.end_ptr = NULL;
	write_queue.start_ptr = NULL;
	write_queue.end_ptr = NULL;
}

static unsigned int is_buffer_enough(struct swap_subbuffer *subbuffer,
				     size_t size)
{
	/* XXX Think about checking full_buffer_part for correctness 
	 * (<queue_subbuffer_size). It should be true, but if isn't (due to sources
	 * chaning, etc.) this function should be true! */
	return ((queue_subbuffer_size-subbuffer->full_buffer_part) >= size) ? 1 : 0;
}

/* Get first subbuffer from read list */
struct swap_subbuffer *get_from_read_list(void)
{
	struct swap_subbuffer *result = NULL;

	/* Lock read sync primitive */
	sync_lock(&read_queue.queue_sync);

	if (read_queue.start_ptr == NULL) {
		result = NULL;
		goto get_from_read_list_unlock;
	}

	result = read_queue.start_ptr;

	/* If this is the last readable buffer, read_queue.start_ptr next time will 
	 * points to NULL and that case is handled in the beginning of function
	 */
	if (read_queue.start_ptr == read_queue.end_ptr) {
		read_queue.end_ptr = NULL;
	}
	read_queue.start_ptr = read_queue.start_ptr->next_in_queue;

get_from_read_list_unlock:
	/* Unlock read sync primitive */
	sync_unlock(&read_queue.queue_sync);

	return result;
}

/* Add subbuffer to read list */
void add_to_read_list(struct swap_subbuffer *subbuffer)
{

	/* Lock read sync primitive */
	sync_lock(&read_queue.queue_sync);

	if (!read_queue.start_ptr)
		read_queue.start_ptr = subbuffer;

	if (read_queue.end_ptr) {
		read_queue.end_ptr->next_in_queue = subbuffer;

		read_queue.end_ptr = read_queue.end_ptr->next_in_queue;
	} else {
		read_queue.end_ptr = subbuffer;
	}
	read_queue.end_ptr->next_in_queue = NULL;

	/* Unlock read sync primitive */
	sync_unlock(&read_queue.queue_sync);
}

/* Call add to read list and callback function from driver module */
int add_to_read_list_with_callback(struct swap_subbuffer *subbuffer)
{
	int result = 0;

	add_to_read_list(subbuffer);
	// TODO Handle ret value
	result = swap_buffer_callback(subbuffer);

	return result;
}

/* Get first writable subbuffer from write list */
struct swap_subbuffer *get_from_write_list(size_t size, void **ptr_to_write)
{
	struct swap_subbuffer *result = NULL;

	/* Callbacks are called at the end of the function to prevent deadlocks */
	struct queue callback_queue = {
		.start_ptr = NULL,
		.end_ptr = NULL,
		.queue_sync = {
			.flags = 0x0
		}
	};
	struct swap_subbuffer *tmp_buffer = NULL;

	/* Init pointer */
	*ptr_to_write = NULL;

	/* Lock write list sync primitive */
	sync_lock(&write_queue.queue_sync);

	while (write_queue.start_ptr) {
		/* If start points to NULL => list is empty => exit */
		if (!write_queue.start_ptr) {
			result = NULL;
			goto get_from_write_list_unlock;
		}

		/* We're found subbuffer */
		if (is_buffer_enough(write_queue.start_ptr, size)) {

			result = write_queue.start_ptr;
			*ptr_to_write = (void *)((unsigned long)
						 (buffer_address(result->data_buffer)) +
						 result->full_buffer_part);

			/* Add data size to full_buffer_part. Very important to do it in
			 * write_queue.queue_sync spinlock */
			write_queue.start_ptr->full_buffer_part += size;

			/* Lock rw sync. Should be unlocked in swap_buffer_write() */
			sync_lock(&result->buffer_sync);
			break;
		/* This subbuffer is not enough => it goes to read list */
		} else {
			result = write_queue.start_ptr;

			/* If we reached end of the list */
			if (write_queue.start_ptr == write_queue.end_ptr) {
				write_queue.end_ptr = NULL;
			}

			/* Move start write pointer */
			write_queue.start_ptr = write_queue.start_ptr->next_in_queue;

			/* Add to callback list */
			if (!callback_queue.start_ptr)
				callback_queue.start_ptr = result;

			if (callback_queue.end_ptr)
				callback_queue.end_ptr->next_in_queue = result;
			callback_queue.end_ptr = result;
			callback_queue.end_ptr->next_in_queue = NULL;
			result = NULL;
		}
	}

get_from_write_list_unlock:
	/* Unlock write list sync primitive */
	sync_unlock(&write_queue.queue_sync);

	/* Adding buffers to read list and calling callbacks */
	for (tmp_buffer = NULL; callback_queue.start_ptr; ) {
		if (callback_queue.start_ptr == callback_queue.end_ptr)
			callback_queue.end_ptr = NULL;

		tmp_buffer = callback_queue.start_ptr;
		callback_queue.start_ptr = callback_queue.start_ptr->next_in_queue;

		add_to_read_list_with_callback(tmp_buffer);
	}

	return result;
}

/* Add subbuffer to write list */
void add_to_write_list(struct swap_subbuffer *subbuffer)
{
	sync_lock(&write_queue.queue_sync);

	/* Reinitialize */
	// TODO Useless memset
//	memset(buffer_address(subbuffer->data_buffer), 0, queue_subbuffer_size);
	subbuffer->full_buffer_part = 0;

	if (!write_queue.start_ptr)
		write_queue.start_ptr = subbuffer;

	if (write_queue.end_ptr) {
		write_queue.end_ptr->next_in_queue = subbuffer;
		write_queue.end_ptr = write_queue.end_ptr->next_in_queue;
	} else {
		write_queue.end_ptr = subbuffer;
	}
	write_queue.end_ptr->next_in_queue = NULL;

	sync_unlock(&write_queue.queue_sync);
}

/* Add subbuffer to busy list when it is read from out of the buffer */
void add_to_busy_list(struct swap_subbuffer *subbuffer)
{
	/* Lock busy sync primitive */
	sync_lock(&buffer_busy_sync);

	subbuffer->next_in_queue = NULL;
	queue_busy[queue_busy_last_element] = subbuffer;
	queue_busy_last_element += 1;

	/* Unlock busy sync primitive */
	sync_unlock(&buffer_busy_sync);
}

/* Remove subbuffer from busy list when it is released */
int remove_from_busy_list(struct swap_subbuffer *subbuffer)
{
	int result = E_SB_NO_SUBBUFFER_IN_BUSY; // For sanitization
	int i;

	/* Lock busy list sync primitive */
	sync_lock(&buffer_busy_sync);

	/* Sanitization and removing */
	for (i = 0; i < queue_busy_last_element; i++) {
		if (queue_busy[i] == subbuffer) {
			/* Last element goes here and length is down 1 */
			queue_busy[i] = queue_busy[queue_busy_last_element - 1];
			queue_busy_last_element -= 1;
			result = E_SB_SUCCESS;
			break;
		}
	}

	/* Unlock busy list sync primitive */
	sync_unlock(&buffer_busy_sync);

	return result;
}

/* Get subbuffers count in read list */
/* XXX Think about locks */
int get_full_buffers_count(void)
{
	int result = 0;
	struct swap_subbuffer *buffer = read_queue.start_ptr;

	while (buffer && buffer->full_buffer_part) {
		result += 1;
		buffer = buffer->next_in_queue;
	}

	return result;
}

/* Set all subbuffers in write list to read list */
void set_all_to_read_list(void)
{
	struct swap_subbuffer *buffer = write_queue.start_ptr;

	/* Locking write sync primitive */
	sync_lock(&write_queue.queue_sync);

	while (write_queue.start_ptr) {
		/* Waiting till semaphore should be posted */

// TODO To think: It's not bad as it is, but maybe it would be better locking
// semaphore while changing its list? (Not bad now, cause buffer should have
// already been stopped).

		sync_lock(&buffer->buffer_sync);

		sync_unlock(&buffer->buffer_sync);

		buffer = write_queue.start_ptr;

		/* If we reached end of the list */
		if (write_queue.start_ptr == write_queue.end_ptr) {
			write_queue.end_ptr = NULL;
		}
		write_queue.start_ptr = write_queue.start_ptr->next_in_queue;

		add_to_read_list(buffer);
	}

	/* Unlocking write primitive */
	sync_unlock(&write_queue.queue_sync);
}

/* Get subbuffers count in busy list */
/* XXX Think abount lock */
int get_busy_buffers_count(void)
{
	return queue_busy_last_element;
}

/* Get memory pages count in subbuffer */
int get_pages_count_in_subbuffer(void)
{
/* Return 1 if pages order 0, or 2 of power pages_order_in_subbuffer otherwise */
	return (pages_order_in_subbuffer) ? 2 << (pages_order_in_subbuffer - 1) : 1;
}
