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

/* SWAP Buffer interface implementation */

#include "swap_buffer_module.h"
#include "buffer_queue.h"
#include "buffer_description.h"
#include "space_dep_operations.h"

#define BUFFER_WORK 1
#define BUFFER_STOP 0

typedef int(*subbuffer_callback_type)(void*);
typedef unsigned char buffer_status;

static subbuffer_callback_type subbuffer_callback = NULL;   //Callback, called
                                                            //when new readalbe
                                                            //subbuffer appears
static size_t subbuffers_size = 0;                          //Subbuffers size
static unsigned int subbuffers_num = 0;                     //Subbuffres count
static buffer_status swap_buffer_status = BUFFER_STOP;      //Buffer status

//static buffer_access_sync_type buffer_sync;

//TODO Swap restart

static inline int are_two_regions_overlap(const void* region1,
                                          const void* region2, size_t size)
{
    int i;

    for (i = 0; i < size; i++) {
        if ((region1 + i == region2) || (region1 + i == region2)) {
            return 1;
        }
    }

    return 0;
}

int swap_buffer_init(size_t subbuffer_size, unsigned int nr_subbuffers,
                     int (*subbuffer_full_callback)(void))
{
    int result = 0;

    /*  >0 - mem pages in one subbuffer
     */

    // TODO Different initialization for first one and initialization after stop
    // TODO Test if wrong function type
    subbuffer_callback = (subbuffer_callback_type)subbuffer_full_callback;
    subbuffers_size = subbuffer_size;
    subbuffers_num = nr_subbuffers;

    result = buffer_queue_allocation(subbuffers_size, subbuffers_num);
    if (result < 0) {
        return result;
    }

    swap_buffer_status = BUFFER_WORK;
    result = get_pages_in_subbuffer();

    return result;
}

int swap_buffer_uninit(void)
{
    int result;

    /*  0 - ok
     * -1 - not all buffers released
     * 2 - mutex_destroy failed
     */

    /* Stop swap_buffer */
    swap_buffer_status = BUFFER_STOP;

    /* Checking whether all buffers are released */
    if (get_busy_buffers_count()) {
        result = -1;
        return result;
    }

    /* Free */
    result = buffer_queue_free();

    subbuffer_callback = NULL;
    subbuffers_size = 0;
    subbuffers_num = 0;

//TODO 
/*#ifdef BUFFER_FOR_USER
    if (pthread_mutex_destroy(&buffer_sync)) {
        result = 2;
        return result;
    }

// TODO Think for spinlock*/
//#endif /* BUFFER_FOR_USER */

    return result;
}

ssize_t swap_buffer_write(size_t size, void* data)
{
    int result = 0;
    struct swap_buffer* buffer_to_write = NULL;

    /* >0 - ok, written size
     * -1 - no buffers in write list
     * -2 - wrong size
     * -3 - swap_buffer stopped
     * -4 - cannot lock semaphore
     * -5 - cannot unlock semaphore
     * -6 - regions are overlapping
     */

    /* Check buffer status */
    if (!(swap_buffer_status & BUFFER_WORK)) {
        result = -3;
        return result;
    }

    /* Size sanitization */
    if ((size > subbuffers_size) || (size == 0)) {
        result = -2;
        return result;
    }

    /* Get next write buffer and occupying semaphore */
    buffer_to_write = get_from_write_list(size);
    if (!buffer_to_write) {
        result = -1;
        return result;
    }

    /* Check for overlapping */
    if (are_two_regions_overlap(buffer_address(buffer_to_write->buffer) +
                                buffer_to_write->full_buffer_part, data,
                                size)) {
        result = -6;
        goto buf_write_sem_post;
    }

    /* Copy data to buffer */
    /* XXX Think of using memmove instead */
    memcpy((void*)((unsigned long)(buffer_address(buffer_to_write->buffer)) +
           buffer_to_write->full_buffer_part), data, size);

    /* Inc buffer full part size */
    buffer_to_write->full_buffer_part += size;

    result = size;

    /* Unlock semaphpore (Locked in get_from_write_list()) */
buf_write_sem_post:
    if (buffer_rw_unlock(&buffer_to_write->buffer_sync)) {
        result = -5;
        return result;
    }

    return result;
}

int swap_buffer_get(struct swap_buffer** subbuffer)
{
    int result = 0;
    struct swap_buffer* buffer_to_read = NULL;

    /* >0 - page count in subbuffer (in kernel) or 0 (in user)
     * -1 - no buffer for reading
     * -2 - problems with add_to_busy_list
     */

    /* Get next read buffer */
    buffer_to_read = get_from_read_list();
    if (!buffer_to_read) {
        result = -1;
        return result;
    }

    /* Add to busy list */
    buffer_to_read->next_in_queue = NULL;
    if (add_to_busy_list(buffer_to_read) < 0) {
        result = -2;
        return result;
    }

    // TODO Useless check
    if (!result) {
        *subbuffer = buffer_to_read;
    }

    return get_pages_in_subbuffer();
}

int swap_buffer_release(struct swap_buffer** subbuffer)
{
    int result = 0;

    /*  0 - ok
     * -1 - can't remove from busy list!
     * -2 - can't add to write list
     */

    /* Remove from busy list (includes sanitization) */
    if (remove_from_busy_list(*subbuffer) < 0) {
        result = -1;
        return result;
    }

    /* Add to write list */
    if (add_to_write_list(*subbuffer) < 0) {
        result = -2;
        return result;
    }

    return result;
}

int swap_buffer_flush(struct swap_buffer ***subbuffers)
{
    int result = 0;

    /* >=0 - buffers count
     * <0  - set_all_to_read_list() error code
     */

    /* Stop swap_buffer */
    swap_buffer_status = BUFFER_STOP;

    /* Set all write buffers to read list */
    result = set_all_to_read_list();
    if (result < 0) {
        return result;
    }

    /* Get count of all full buffers */
    result = get_full_buffers_count();
    if (result <= 0) {
        result = 0;
        return result;
    }

// Relict code, not used now. You can just enjoy how it was some time before.
//
//    /* Memory allocation for swap_buffer structures array.
//     * Must be freed in module that called this one */
//    *subbuffers = memory_allocation(sizeof(struct swap_buffer*) * result);
//    if (!(*subbuffers)) {
//        result = -1;
//        return result;
//    }
//
//    /* Adding all subbufers from read list to subbuffers array */
//    do {
//        i++;
//        (*subbuffers)[i] = get_from_read_list(); //TODO Are we need mutex? 
//                                                 //Buffer stopped - nobody's
//                                                 //writing
//    } while ((*subbuffers)[i]);

    return result;
}

int swap_buffer_callback(void *buffer)
{
    int result;

    /*   0 - ok
     *  <0 - subbuffer_callback error
     * -99 - subbuffer_callback is not registered */

    if (!subbuffer_callback) {
        return -99;
    }

    result = subbuffer_callback(buffer);
    if (result < 0) {
        print_err("Callback error! Error code: %d\n", result);
    }

    return result;
}

#ifndef BUFFER_FOR_USER
EXPORT_SYMBOL_GPL(swap_buffer_init);
EXPORT_SYMBOL_GPL(swap_buffer_uninit);
EXPORT_SYMBOL_GPL(swap_buffer_write);
EXPORT_SYMBOL_GPL(swap_buffer_get);
EXPORT_SYMBOL_GPL(swap_buffer_release);
EXPORT_SYMBOL_GPL(swap_buffer_flush);
#endif /* BUFFER_FOR_USER */

SWAP_BUFFER_MODULE_INFORMATION
