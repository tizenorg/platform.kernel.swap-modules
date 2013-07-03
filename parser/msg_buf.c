#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "msg_buf.h"

int init_mb(struct msg_buf *mb, size_t size)
{
	if (size) {
		mb->begin = vmalloc(size);
		if (mb->begin == NULL) {
			printk("Cannot alloc memory!\n");
			return -ENOMEM;
		}

		mb->ptr = mb->begin;
		mb->end = mb->begin + size;
	} else
		mb->begin = mb->end = mb->ptr = NULL;

	return 0;
}

void uninit_mb(struct msg_buf *mb)
{
	vfree(mb->begin);
}

int cmp_mb(struct msg_buf *mb, size_t size)
{
	char *tmp;

	tmp = mb->ptr + size;
	if (mb->end > tmp)
		return 1;
	else if (mb->end < tmp)
		return -1;

	return 0;
}

size_t remained_mb(struct msg_buf *mb)
{
	return mb->end - mb->ptr;
}

int get_u32(struct msg_buf *mb, u32 *val)
{
	if (cmp_mb(mb, sizeof(*val)) < 0)
		return -EINVAL;

	*val = *((u32 *)mb->ptr);
	mb->ptr += sizeof(*val);

	return 0;
}

int get_u64(struct msg_buf *mb, u64 *val)
{
	if (cmp_mb(mb, sizeof(*val)) < 0)
		return -EINVAL;

	*val = *((u64 *)mb->ptr);
	mb->ptr += sizeof(*val);

	return 0;
}

int get_string(struct msg_buf *mb, char **str)
{
	size_t len, len_max;

	len_max = mb->end - mb->ptr - 1;
	if(len_max < 0)
		return -EINVAL;

	len = strlen(mb->begin) + 1;

	*str = kmalloc(len, GFP_KERNEL);
	if (*str == NULL)
		return -ENOMEM;

	memcpy(*str, mb->begin, len);
	mb->ptr += len;

	return 0;
}

void put_strung(char *str)
{
	kfree(str);
}
