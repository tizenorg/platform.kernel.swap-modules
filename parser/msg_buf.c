/*
 *  SWAP Parser
 *  modules/parser/msg_buf.c
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
 * 2013	 Vyacheslav Cherkashin, Vitaliy Cherepanov: SWAP Parser implement
 *
 */


#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "msg_buf.h"
#include "parser_defs.h"

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

int is_end_mb(struct msg_buf *mb)
{
	return mb->ptr == mb->end;
}

int get_u8(struct msg_buf *mb, u8 *val)
{
	if (cmp_mb(mb, sizeof(*val)) < 0)
		return -EINVAL;

	*val = *((u8 *)mb->ptr);
	mb->ptr += sizeof(*val);

	print_parse_debug("u8 ->%d;%08X\n", *val, *val);

	return 0;
}

int get_u32(struct msg_buf *mb, u32 *val)
{
	if (cmp_mb(mb, sizeof(*val)) < 0)
		return -EINVAL;

	*val = *((u32 *)mb->ptr);
	mb->ptr += sizeof(*val);

	print_parse_debug("u32->%d;%08X\n", *val, *val);

	return 0;
}

int get_u64(struct msg_buf *mb, u64 *val)
{
	if (cmp_mb(mb, sizeof(*val)) < 0)
		return -EINVAL;

	*val = *((u64 *)mb->ptr);
	mb->ptr += sizeof(*val);
	print_parse_debug("u64->%llu; 0x%016llX\n", *val, *val);

	return 0;
}

int get_string(struct msg_buf *mb, char **str)
{
	size_t len, len_max;
	enum { min_len_str = 1 };

	if (cmp_mb(mb, min_len_str) < 0)
		return -EINVAL;

	len_max = remained_mb(mb) - 1;
	len = strnlen(mb->ptr, len_max);

	*str = kmalloc(len + 1, GFP_KERNEL);
	if (*str == NULL)
		return -ENOMEM;

	memcpy(*str, mb->ptr, len);
	(*str)[len] = '\0';

	mb->ptr += len + 1;

	print_parse_debug("str->'%s'\n", *str);
	return 0;
}

void put_string(char *str)
{
	kfree(str);
}
