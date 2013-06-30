#include <linux/string.h>
#include <linux/slab.h>
#include <linux/splice.h>
#include <asm/uaccess.h>

#include "driver_defs.h"
#include "swap_driver_errors.h"
#include "../buffer/swap_buffer_module.h" //TODO
#include "../buffer/swap_buffer_errors.h" //TODO
#include "device_driver_to_driver_to_buffer.h"

/* Current busy buffer */
static struct swap_subbuffer *busy_buffer = NULL;

/* Buffers count ready to be read */
static int buffers_to_read = 0;

/* Pages count in one subbuffer */
static int pages_per_buffer = 0;


/* TODO Get subbuffer for reading */
static size_t driver_to_buffer_get(void)
{
    int result;

    /* If there is no readable buffers, return error */
    result = swap_buffer_get(&busy_buffer);
    if (result == -E_SB_NO_READABLE_BUFFERS) {
        busy_buffer = NULL;
        return -E_SD_NO_DATA_TO_READ;
    } else if (result < 0) {
        print_err("swap_buffer_get unhandle error %d\n", result);
        return -E_SD_BUFFER_ERROR;
    }

    return busy_buffer->full_buffer_part;
}

/* TODO Release subbuffer */
static int driver_to_buffer_release(void)
{
    int result;

    if (!busy_buffer)
        return -E_SD_NO_BUSY_SUBBUFFER;

    result = swap_buffer_release(&busy_buffer);
    if (result == -E_SB_NO_SUBBUFFER_IN_BUSY) {
        return -E_SD_WRONG_SUBBUFFER_PTR;
    } else if (result < 0) {
        print_err("swap_buffer_release unhandle error %d\n", result);
        return -E_SD_BUFFER_ERROR;
    }

    busy_buffer = NULL;

    return E_SD_SUCCESS;
}

/* Buffers callback function */
int driver_to_buffer_callback(void)
{
//XXX: Think of sync with get next
    int result;

    /* Increment buffers_to_read counter */
    buffers_to_read++;
    swap_device_wake_up_process();

    return E_SD_SUCCESS;
}

/* Write to buffers */
ssize_t driver_to_buffer_write(size_t size, void* data)
{
    ssize_t result;

    result = swap_buffer_write(size, data);
    if (result == -E_SB_IS_STOPPED) {
        print_err("Buffer is not run! Initialize it before writing\n");
        return -E_SD_WRITE_ERROR;
    } else if (result < 0) {
        print_err("swap_buffer_write error %d\n", result);
        return -E_SD_WRITE_ERROR;
    }

    return result;
}

/* Read buffers */
ssize_t driver_to_buffer_read(char __user *buf, size_t count)
{
    size_t bytes_to_copy;
    size_t bytes_to_read = 0;
    int page_counter = 0;

    /* Reading from swap_device means reading only current busy_buffer. So, if
     * there is no busy_buffer, we don't get next to read, we just read nothing.
     * In this case, or if there is nothing to read from busy_buffer - return
     * -E_SD_NO_DATA_TO_READ. It should be correctly handled in device_driver */
    if (!busy_buffer || !busy_buffer->full_buffer_part)
        return -E_SD_NO_DATA_TO_READ;

    /* Bytes count that we're going to copy to user buffer is equal to user
     * buffer size or to subbuffer readable size whichever is less */
    bytes_to_copy = (count > busy_buffer->full_buffer_part) ?
                    busy_buffer->full_buffer_part : count;

    /* Copy data from each page to buffer */
    while(bytes_to_copy > 0) {
        /* Get size that should be copied from current page */
        size_t read_from_this_page = (bytes_to_copy > PAGE_SIZE) ? PAGE_SIZE
                                                                 : bytes_to_copy;

        /* Copy and add size to copied bytes count */

        // TODO Check with more than one page
        bytes_to_read += read_from_this_page -
                         copy_to_user(buf, page_address(busy_buffer->data_buffer) +
                                                        (sizeof(struct page*) *
                                                         page_counter),
                                                        read_from_this_page);
        bytes_to_copy -= read_from_this_page;
        page_counter++;
    }

    return bytes_to_read;
}

/* Flush swap_buffer */
int driver_to_buffer_flush(void)
{
    int result;

    result = swap_buffer_flush();

    if (result >= 0)
        buffers_to_read = result;
    else if (result < 0)
        return -E_SD_BUFFER_ERROR;

    swap_device_wake_up_process();

    return E_SD_SUCCESS;
}

/* Fills page and partial arrays in splice_pipe_desc struct for splice_read */
int driver_to_buffer_fill_pages_arrays(struct page ***pages,
                                       struct partial_page **partial)
{
    int page_counter = 0;
    size_t data_to_splice;

    /* Sanitization */
    if (!busy_buffer || !busy_buffer->full_buffer_part)
        return -E_SD_NO_BUSY_SUBBUFFER;

    data_to_splice = busy_buffer->full_buffer_part;

    /* Allocate memory for arrays */
    *pages = kmalloc(sizeof(struct page*) * pages_per_buffer, GFP_KERNEL);
    *partial = kmalloc(sizeof(struct partial_page) * pages_per_buffer, GFP_KERNEL);

    while (data_to_splice) {
        /* Get bytes count that are should be read from current page */
        size_t read_from_current_page = (data_to_splice > PAGE_SIZE) ? PAGE_SIZE
                                        : data_to_splice;

        /* Fill pages array */
        (*pages)[page_counter] = &busy_buffer->data_buffer[page_counter];

        /* Offset is always 0, cause we write to buffers from the very beginning
         * of the first page */
        (*partial)[page_counter].offset = 0;
        (*partial)[page_counter].len = read_from_current_page;

        /* TODO Private not used */
        (*partial)[page_counter].private = 0;

        page_counter++;
        data_to_splice -= read_from_current_page;
    }
    return page_counter;
}

/* Check for subbuffers ready to be read */
int driver_to_buffer_buffer_to_read(void)
{
    return busy_buffer ? 1 : 0;
}

/* Set buffers size and count */
int driver_to_buffer_initialize(size_t size, unsigned int count)
{
    int result;

    if (size == 0 && count == 0) {
        return -E_SD_WRONG_ARGS;
    }

    result = swap_buffer_init(size, count, (void*)&driver_to_buffer_callback);
    if (result == -E_SB_NO_MEM_QUEUE_BUSY
        || result == -E_SB_NO_MEM_BUFFER_STRUCT) {
        return -E_SD_NO_MEMORY;
    }

    // TODO Race condition: buffer can be used in other thread till we're in
    // this func
    /* Initialize driver_to_buffer variables */
    pages_per_buffer = result;
    busy_buffer = NULL;
    buffers_to_read = 0;

    return E_SD_SUCCESS;
}

/* Uninitialize buffer */
int driver_to_buffer_uninitialize(void)
{
    int result;

    /* Release occupied buffer */
    if (busy_buffer) {
        result = driver_to_buffer_release();
        // TODO Maybe release anyway
        if (result < 0) {
            return result;
        }
        busy_buffer = NULL;
    }

    result = swap_buffer_uninit();
    if (result == -E_SB_UNRELEASED_BUFFERS) {
        print_err("Can't uninit buffer! There are busy subbuffers!\n");
        result = -E_SD_BUFFER_ERROR;
    } else if (result < 0) {
        print_err("swap_buffer_uninit error %d\n", result);
        result = -E_SD_BUFFER_ERROR;
    } else {
        result = E_SD_SUCCESS;
    }

    /* Reinit driver_to_buffer vars */
    buffers_to_read = 0;
    pages_per_buffer = 0;

    return result;
}

/* Get next buffer to read */
int driver_to_buffer_next_buffer_to_read(void)
{
//XXX: Think of sync with callback
    int result;

    /* If there is busy_buffer first release it */
    if (busy_buffer) {
        print_debug(" There are busy subbuffer!\n");
        result = driver_to_buffer_release();
        if (result)
            return result;
    }

    /* If there is no buffers to read, return E_SD_NO_DATA_TO_READ.
     * SHOULD BE POSITIVE, cause there is no real error. */
    if (!buffers_to_read) {
        return E_SD_NO_DATA_TO_READ;
    }

    /* Get next buffer to read */
    result = driver_to_buffer_get();
    if (result < 0) {
        print_err("buffer_to_reads > 0, but there are no buffers to read\n");
        return result;
    }

    /* Decrement buffers_to_read counter */
    buffers_to_read--;

    return E_SD_SUCCESS;
}

