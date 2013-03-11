#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include "error_storage.h"

static int create_errno_buffer(void);
static void delete_errno_buffer(void);
static unsigned int get_max_error_buffer_size(void);

struct errno_struct
{
        unsigned int size;
        char *buffer;
};

static struct errno_struct *last_error = NULL;

static int create_errno_buffer(void)
{
        struct errno_struct *error = NULL;
        if (last_error != NULL){
                return -1;
	}
        error = (struct errno_struct*)vmalloc(sizeof(struct errno_struct));
        if (error == NULL){
                return -1;
	}
        error->buffer = vmalloc(MAX_ERROR_BUF_PATH);
        if (error->buffer == NULL)
        {
                vfree(error);
                return -1;
        }
        error->buffer[0] = '\0';
        error->size = 0;
        last_error = (struct errno_struct*) error;

        return 0;
}

static unsigned int get_max_error_buffer_size(void)
{
	return (unsigned int)MAX_ERROR_BUF_PATH;
}

int update_errno_buffer(const char *buffer)
{
        unsigned int size;

        if (last_error == NULL)
        {
                if (create_errno_buffer() != 0)
                        return -1;
        }

        size = strlen(buffer);

        if (last_error->size + size + 1 >= get_max_error_buffer_size()) {
                return -1;
	}

        strncat((char*)(last_error->buffer), buffer, size);

        last_error->size += size + 1;
        last_error->buffer[last_error->size - 1] = ',';
        last_error->buffer[last_error->size] = '\0';

        return 0;
}

static void delete_errno_buffer(void)
{
        if (last_error == NULL)
                return;

        vfree((char*)last_error->buffer);
        vfree(last_error);

        last_error = NULL;

        return;
}

int get_last_error(void* u_addr)
{
        int result;

        if (last_error == NULL)
                return -1;

        result = copy_to_user ((void*)u_addr, (void*)(last_error->buffer), last_error->size + 1);
        if (result) {
                result = -EFAULT;
        }

        delete_errno_buffer();

        return result;
}

int has_last_error()
{
        if(last_error == NULL)
                return 0;
        return -1;
}
