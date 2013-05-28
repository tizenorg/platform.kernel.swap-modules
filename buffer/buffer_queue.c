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
 * 2013         Alexander Aksenov <a.aksenov@samsung.com>: SWAP Buffer implement
 *
 */

/* SWAP buffer queues implementation */

/* For all memory allocation/deallocation operations, except buffer memory
 * allocation/deallocation should be used 
 *  memory_allocation(size_t memory_size)
 *  memory_free(void* ptr)
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
#include "buffer_description.h"
#include "swap_buffer_to_buffer_queue.h"
#include "space_dep_operations.h"

typedef struct swap_buffer* write_start_ptr_type;
typedef struct swap_buffer* write_end_ptr_type;
typedef struct swap_buffer* read_start_ptr_type;
typedef struct swap_buffer* read_end_ptr_type;

static write_start_ptr_type queue_write_start_ptr = NULL;   //Points to the
                                                            //write queue first
                                                            //element
static write_end_ptr_type queue_write_end_ptr = NULL;       //Points to the
                                                            //write queue last
                                                            //element
static read_start_ptr_type queue_read_start_ptr = NULL;     //Points to the read
                                                            //queue first 
                                                            //element
static read_end_ptr_type queue_read_end_ptr = NULL;         //Points to the read
                                                            //queue last element
static struct swap_buffer** queue_busy = NULL;          //Pointers array. Points
                                                        //to occupied buffers
static unsigned int queue_busy_last_element;            //Store last occupied
                                                        //element in queue_busy
static unsigned int queue_subbuffer_count = 0;          //Subbuffers count
static size_t queue_subbuffer_size = 0;                 //Subbuffers size
static buffer_access_sync_type buffer_read_sync;        //add_to_read_list and
                                                        //get_from_read_list 
                                                        //sync
static buffer_access_sync_type buffer_write_sync;       //add_to_write_list and
                                                        //get_from_write_list
                                                        //sync
static buffer_access_sync_type buffer_busy_sync;        //add_to_busy_list and
                                                        //remove_from_busy_list
                                                        //sync
static int pages_order_in_subbuffer = 0;                //Page count in one
                                                        //subbuffer


int buffer_queue_allocation(const size_t subbuffer_size,
                            const unsigned int subbuffers_count)
{
    int result = 0;
    int i;

    /*  0 - ok
     * -1 - memory for queue_busy wasn't allocated
     * -2 - memory for swap_buffer structure wasn't allocated
     * -3 - memory for buffer wasn't allocated
     * -4 - semaphore cannot be inited
     * -5 - sync primitives cannot be inited
     */

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
    if (buffer_access_init(&buffer_read_sync)) {
        result = -5;
        return result;
    }
    if (buffer_access_init(&buffer_write_sync)) {
        result = -5;
        return result;
    }
    if (buffer_access_init(&buffer_busy_sync)) {
        result = -5;
        return result;
    }

    /* Memory allocation for queue_busy */
    queue_busy = memory_allocation(sizeof(struct swap_buffer*) *
                                   queue_subbuffer_count);

    if (!queue_busy) {
        result = -1;
        return result;
    }

    /* Memory allocation for swap_buffer structures */
    /* Allocation for first structure. */

    queue_write_start_ptr = memory_allocation(sizeof(struct swap_buffer));

    if (!queue_write_start_ptr) {
        result = -2;
        memory_free(queue_busy);
        queue_busy = NULL;
        return result;
    }
    queue_write_end_ptr = queue_write_start_ptr;

    queue_write_end_ptr->next_in_queue = NULL;
    queue_write_end_ptr->full_buffer_part = 0;
    queue_write_end_ptr->buffer = buffer_allocation(queue_subbuffer_size);
    if (!queue_write_end_ptr->buffer) {
        print_err("Cannot allocate memory for buffer 1\n");
        result = -3;
        memory_free(queue_busy);
        memory_free(queue_write_start_ptr);
        queue_write_start_ptr = NULL;
        queue_busy = NULL;

        return result;
    }

    print_msg(" Buffer allocated = 0x%x\n", (unsigned long)queue_write_end_ptr->buffer);

    if (buffer_rw_init(&queue_write_end_ptr->buffer_sync) != 0) {
        result = -4;
        memory_free(queue_busy);
        queue_busy = NULL;
        memory_free(queue_write_start_ptr);
        queue_write_start_ptr = NULL;
        return result;
    }

    /* Buffer initialization */
    memset(buffer_address(queue_write_end_ptr->buffer), 0, queue_subbuffer_size);

    /* Allocation for other structures. */
    for (i = 1; i < queue_subbuffer_count; i++) {
        queue_write_end_ptr->next_in_queue = memory_allocation(sizeof(struct swap_buffer));
        if (!queue_write_end_ptr->next_in_queue) {
        /* Free all previously allocated memory */
            int j;
            struct swap_buffer *clean_tmp_struct = queue_write_start_ptr;

            result = -2;
            for (j = 0; j < i; j++) {
                clean_tmp_struct = queue_write_start_ptr;
                if (queue_write_start_ptr != queue_write_end_ptr) {
                    queue_write_start_ptr = queue_write_start_ptr->next_in_queue;
                }
                buffer_free(clean_tmp_struct->buffer,queue_subbuffer_size);
                memory_free(clean_tmp_struct);
            }
            queue_write_end_ptr = NULL;
            queue_write_start_ptr = NULL;
            memory_free(queue_busy);
            queue_busy = NULL;
            return result;
        }

        /* Now next queue_write_end_ptr is next */
        queue_write_end_ptr = queue_write_end_ptr->next_in_queue;

        queue_write_end_ptr->next_in_queue = NULL;
        queue_write_end_ptr->full_buffer_part = 0;
        queue_write_end_ptr->buffer = buffer_allocation(queue_subbuffer_size);
        if (!queue_write_end_ptr->buffer) {
        /* Free all previously allocated memory */
            int j;
            struct swap_buffer *clean_tmp_struct = queue_write_start_ptr;

            result = -3;
            print_err("Cannot allocate memory for buffer %d\n", i+1);

            for (j = 0; j < i; j++) {
                clean_tmp_struct = queue_write_start_ptr;
                if (queue_write_start_ptr != queue_write_end_ptr) {
                    queue_write_start_ptr = queue_write_start_ptr->next_in_queue;
                    buffer_free(clean_tmp_struct->buffer, queue_subbuffer_size);
                }
                memory_free(clean_tmp_struct);
            }
            queue_write_end_ptr = NULL;
            queue_write_start_ptr = NULL;
            memory_free(queue_busy);
            queue_busy = NULL;
            return result;
        }

        print_msg(" Buffer allocated = 0x%x, pages_order = %d\n", (unsigned long)queue_write_end_ptr->buffer, pages_order_in_subbuffer);

        if (buffer_rw_init(&queue_write_end_ptr->buffer_sync) != 0) {
        /* Free all previously allocated memory */
            int j;
            struct swap_buffer *clean_tmp_struct = queue_write_start_ptr;

            result = -4;
            for (j = 0; j < i; j++) {
                clean_tmp_struct = queue_write_start_ptr;
                if (queue_write_start_ptr != queue_write_end_ptr) {
                    queue_write_start_ptr = queue_write_start_ptr->next_in_queue;
                }
                buffer_free(clean_tmp_struct->buffer, queue_subbuffer_size);
                memory_free(clean_tmp_struct);
            }
            queue_write_end_ptr = NULL;
            queue_write_start_ptr = NULL;
            memory_free(queue_busy);
            queue_busy = NULL;
            return result;
        }

        /* Buffer initialization */
        memset(buffer_address(queue_write_end_ptr->buffer), 0,
               queue_subbuffer_size);
    }

    return result;
}

int buffer_queue_free(void)
{
    int result = 0;
    struct swap_buffer* tmp = NULL;

    /*  0 - ok
     * <0 - set_all_to_read_list() error
     */

    //TODO Lock read list semaphore to prevent getting subbuffer from read list 
    /* Set all write buffers to read list */
    result = set_all_to_read_list();

    if (result < 0) {
        return result;
    }

    /* Free buffers and structures memory that are in read list */
    while (queue_read_start_ptr) {
        tmp = queue_read_start_ptr;
        queue_read_start_ptr = queue_read_start_ptr->next_in_queue;
        buffer_free(tmp->buffer, queue_subbuffer_size);
        memory_free(tmp);
    }

    /* Free busy_list */
    memory_free(queue_busy);
    queue_busy = NULL;

    queue_subbuffer_size = 0;
    queue_subbuffer_count = 0;
    queue_read_start_ptr = NULL;
    queue_read_end_ptr = NULL;
    queue_write_start_ptr = NULL;
    queue_write_end_ptr = NULL;

    return result;
}

static unsigned int is_buffer_enough(struct swap_buffer* subbuffer, size_t size)
{
    return ((queue_subbuffer_size-subbuffer->full_buffer_part) >= size) ? 1 : 0;
}

/* Get first subbuffer from read list */
struct swap_buffer* get_from_read_list(void)
{
    struct swap_buffer* result = NULL;

    /* Lock read sync primitive */
    if (buffer_access_lock(&buffer_read_sync)) {
        return NULL;
    }

    if (queue_read_start_ptr == NULL) {
        result = NULL;
        goto get_from_read_list_unlock;
    }

    result = queue_read_start_ptr;

    /* If this is the last readable buffer, queue_read_start_ptr next time will 
     * points to NULL and that case is handled in the beginning of function
     */
    if (queue_read_start_ptr == queue_read_end_ptr) {
        queue_read_end_ptr = NULL;
    }
    queue_read_start_ptr = queue_read_start_ptr->next_in_queue;

get_from_read_list_unlock:
    /* Unlock read sync primitive */
    if (buffer_access_unlock(&buffer_read_sync)) {
        return NULL;
    }

    return result;
}

/* Add subbuffer to read list */
int add_to_read_list(struct swap_buffer* subbuffer)
{
    int result = 0;

    /* 0 - ok
     * 1 - cannot lock
     * 2 - cannot unlock */

    /* Lock read sync primitive */
    if (buffer_access_lock(&buffer_read_sync)) {
        result = 1;
        return result;
    }

    // TODO Sanitization?
    if (!queue_read_start_ptr) {
        queue_read_start_ptr = subbuffer;
    }

    if (queue_read_end_ptr) {
        queue_read_end_ptr->next_in_queue = subbuffer;

        queue_read_end_ptr = queue_read_end_ptr->next_in_queue;
    } else {
        queue_read_end_ptr = subbuffer;
    }
    queue_read_end_ptr->next_in_queue = NULL;

    /* Unlock read sync primitive */
    if (buffer_access_unlock(&buffer_read_sync)) {
        result = 2;
        return result;
    }

    return result;
}

/* Call add to read list and callback function from driver module */
int add_to_read_list_with_callback(struct swap_buffer* subbuffer)
{
    int result = 0;

    result = add_to_read_list(subbuffer);
    // TODO Handle ret value
    swap_buffer_callback(subbuffer);

    return result;
}

/* Get first writable subbuffer from write list */
struct swap_buffer* get_from_write_list(size_t size)
{
    struct swap_buffer *result = NULL;

    /* Callbacks are called at the end of the function to prevent deadlocks */
    struct swap_buffer *queue_callback_start_ptr = NULL;
    struct swap_buffer *queue_callback_end_ptr = NULL;
    struct swap_buffer *tmp_buffer = NULL;

    /* Lock write list sync primitive */
    if (buffer_access_lock(&buffer_write_sync)) {
        return NULL;
    }

    while (queue_write_start_ptr) {
        /* If start points to NULL => list is empty => exit */
        if (!queue_write_start_ptr) {
            result = NULL;
            goto get_from_write_list_unlock;
        }

        /* Get semaphore value. Useful only if we want buffer to write to
         * several buffers the same time
         *
         * We're trying to lock semaphore, and if it is successful, unlocking 
         * it. Otherwise, going to the next step. */
        if (buffer_rw_lock(&queue_write_start_ptr->buffer_sync) != 0) {
            // TODO HOW? HOW is it possible to get there?!
            result = queue_write_start_ptr;
            /* If we reached end of the list */
            if (queue_write_start_ptr == queue_write_end_ptr) {
                queue_write_end_ptr = NULL;
            }
            /* Move start write pointer */
            queue_write_start_ptr = queue_write_start_ptr->next_in_queue;

            /* Add to callback list */
            if (!queue_callback_start_ptr) {
                queue_callback_start_ptr = result;
            }
            if (queue_callback_end_ptr) {
                queue_callback_end_ptr->next_in_queue = result;
            }
            queue_callback_end_ptr = result;
            queue_callback_end_ptr->next_in_queue = NULL;

            result = NULL;
            continue;
        }
        buffer_rw_unlock(&queue_write_start_ptr->buffer_sync);

// TODO Do something

        if (is_buffer_enough(queue_write_start_ptr, size)) {
            result = queue_write_start_ptr;
            break;
        } else {
            /* If size is not enough, subbuffers goes to read list */
            result = queue_write_start_ptr;
            /* If we reached end of the list */
            if (queue_write_start_ptr == queue_write_end_ptr) {
                queue_write_end_ptr = NULL;
            }
            /* Move start write pointer */
            queue_write_start_ptr = queue_write_start_ptr->next_in_queue;

            /* Add to callback list */
            if (!queue_callback_start_ptr) {
                queue_callback_start_ptr = result;
            }
            if (queue_callback_end_ptr) {
                queue_callback_end_ptr->next_in_queue = result;
            }
            queue_callback_end_ptr = result;
            queue_callback_end_ptr->next_in_queue = NULL;

            result = NULL;
        }
    }

    /* Lock writing semaphore */
    if (result) {
        if (buffer_rw_lock(&result->buffer_sync)) {
            result = NULL;
            goto get_from_write_list_unlock;
        }
    }

get_from_write_list_unlock:
    /* Unlock write list sync primitive */
    if (buffer_access_unlock(&buffer_write_sync)) {
        if (result) {
            buffer_rw_unlock(&result->buffer_sync);
        }
        return NULL;
    }

    /* Adding buffers to read list and calling callbacks */
    for (tmp_buffer = NULL; queue_callback_start_ptr; ) {

        if (queue_callback_start_ptr == queue_callback_end_ptr) {
            queue_callback_end_ptr = NULL;
        }
        tmp_buffer = queue_callback_start_ptr;
        queue_callback_start_ptr = queue_callback_start_ptr->next_in_queue;

        add_to_read_list_with_callback(tmp_buffer);
    }

    return result;
}

/* Add subbuffer to write list */
int add_to_write_list(struct swap_buffer* subbuffer)
{
    /*  0 - ok
     * -1 - cannot lock
     * -2 - cannot unlock */

    if (buffer_access_lock(&buffer_write_sync)) {
        return -1;
    }

    /* Reinitialize */
    memset(buffer_address(subbuffer->buffer), 0, queue_subbuffer_size);
    subbuffer->full_buffer_part = 0;

    if (!queue_write_start_ptr) {
        queue_write_start_ptr = subbuffer;
    }

    if (queue_write_end_ptr) {
        queue_write_end_ptr->next_in_queue = subbuffer;
        queue_write_end_ptr = queue_write_end_ptr->next_in_queue;
    } else {
        queue_write_end_ptr = subbuffer;
    }
    queue_write_end_ptr->next_in_queue = NULL;

    if (buffer_access_unlock(&buffer_write_sync)) {
        return -2;
    }

    return 0;
}

/* Add subbuffer to busy list when it is read from out of the buffer */
int add_to_busy_list(struct swap_buffer* subbuffer)
{
    /*  0 - ok
     * -1 - cannot lock
     * -2 - cannot unlock */

    /* Lock busy sync primitive */
    if (buffer_access_lock(&buffer_busy_sync)) {
        return -1;
    }

    subbuffer->next_in_queue = NULL;
    queue_busy[queue_busy_last_element] = subbuffer;
    queue_busy_last_element += 1;

    /* Unlock busy sync primitive */
    if (buffer_access_unlock(&buffer_busy_sync)) {
        return -2;
    }

    return 0;
}

/* Remove subbuffer from busy list when it is released */
int remove_from_busy_list(struct swap_buffer* subbuffer)
{
    int result = -1; // For sanitization
    int i;

    /*  0 - ok
     * -1 - no such buffer in queue_busy list
     * -2 - cannot lock
     * -3 - cannot unlock
     */

    /* Lock busy list sync primitive */
    if (buffer_access_lock(&buffer_busy_sync)) {
        result = -2;
        return result;
    }

    /* Sanitization and removing */
    for (i = 0; i < queue_busy_last_element; i++) {
        if (queue_busy[i] == subbuffer) {
            /* Last element goes here and length is down 1 */
            queue_busy[i] = queue_busy[queue_busy_last_element - 1];
            queue_busy_last_element -= 1;
            result = 0;
            break;
        }
    }

    /* Unlock busy list sync primitive */
    if (buffer_access_unlock(&buffer_busy_sync)) {
        result = -3;
        return result;
    }

    return result;
}

/* Get subbuffers count in read list */
/* XXX Think about locks */
int get_full_buffers_count(void)
{
    int result = 0;
    struct swap_buffer* buffer = queue_read_start_ptr;

    /* >=0 - buffers count
     */

    while (buffer && buffer->full_buffer_part) {
        result += 1;
        buffer = buffer->next_in_queue;
    }

    return result;
}

/* Set all subbuffers in write list to read list */
int set_all_to_read_list(void)
{
    int result = 0;
    struct swap_buffer *buffer = queue_write_start_ptr;

    /*  0 - ok
     * -1 - sem_wait() error
     * -2 - sem_post() error
     * -3 - problems with locking sync primitives
     * -4 - problems with unlocking sync primitives
     */

    /* Locking write sync primitive */
    if (buffer_access_lock(&buffer_write_sync)) {
        result = -3;
        return result;
    }

    while (queue_write_start_ptr) {
        /* Waiting till semaphore should be posted */

// TODO To think: It's not bad as it is, but maybe it would be better locking
// semaphore while changing its list? (Not bad now, cause buffer should have
// already been stopped).

        if (buffer_rw_lock(&buffer->buffer_sync)) {
            result = -1;
            goto set_all_to_read_list_unlock;
        }

        if (buffer_rw_unlock(&buffer->buffer_sync)) {
            result = -2;
            goto set_all_to_read_list_unlock;
        }

        buffer = queue_write_start_ptr;

        /* If we reached end of the list */
        if (queue_write_start_ptr == queue_write_end_ptr) {
            queue_write_end_ptr = NULL;
        }
        queue_write_start_ptr = queue_write_start_ptr->next_in_queue;

        add_to_read_list(buffer);
    }

set_all_to_read_list_unlock:
    /* Unlocking write primitive */
    if (buffer_access_unlock(&buffer_write_sync)) {
        result = -4;
    }
    return result;
}

/* Get subbuffers count in busy list */
/* XXX Think abount lock */
int get_busy_buffers_count(void)
{
    return queue_busy_last_element;
}

/* Get memory pages count in subbuffer */
int get_pages_in_subbuffer(void)
{
/* Return 1 if pages order 0, or 2 of power pages_order_in_subbuffer otherwise */
    return (pages_order_in_subbuffer) ? 2 << (pages_order_in_subbuffer - 1) : 1;
}
