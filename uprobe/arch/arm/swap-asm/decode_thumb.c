/*
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
 * Copyright (C) Samsung Electronics, 2015
 *
 * 2015         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/types.h>
#include <linux/errno.h>
#include "decode_thumb.h"
#include "thumb_tramps.h"


#define GET_BIT(x, n)		((x >> n) & 0x1)
#define GET_FIELD(x, s, l)      ((x >> s) & ((1 << l) - 1))
#define SET_FIELD(x, s, l, v)	({		\
	typeof(x) mask = (((1 << l) - 1) << s);	\
	(x & ~mask) | ((v << s) & mask);	\
})


typedef union thumb_insn {
	unsigned long val;
	struct {
		unsigned short hw1;
		unsigned short hw2;
	} __packed;
} thumb_insn_t;

typedef int (*decode_handler_t)(thumb_insn_t insn, struct decode_info *info);


static bool bad_reg(int n)
{
	return n == 13 || n == 15;
}

static int thumb_not_implement(thumb_insn_t insn, struct decode_info *info)
{
	return -EFAULT;
}

static int thumb_unpredictable(thumb_insn_t insn, struct decode_info *info)
{
	return -EINVAL;
}

/* hw1[1110 100x x1xx ????] */
static int t32_ldrd_strd(thumb_insn_t insn, struct decode_info *info)
{
	int w = GET_BIT(insn.hw1, 5);
	int n = GET_FIELD(insn.hw1, 0, 4);
	int t = GET_FIELD(insn.hw2, 12, 4);
	int t2 = GET_FIELD(insn.hw2, 8, 4);

	if (bad_reg(t) || bad_reg(t2))
		return thumb_unpredictable(insn, info);

	/* check load flag */
	if (GET_BIT(insn.hw1, 4)) {
		/* LDRD */
		if ((w && (n == 15)) || t == t2)
			return thumb_unpredictable(insn, info);

		if (n == 15) {
			/* change PC -> SP */
			insn.hw1 = SET_FIELD(insn.hw1, 0, 4, 13);
			tt_make_pc_deps(info->tramp, insn.val,
					info->vaddr, true);

			return 0;
		}
	} else {
		/* STRD */
		if ((w && t == n) || (w && t2 == n) || (n == 15))
			return thumb_unpredictable(insn, info);
	}

	tt_make_common(info->tramp, insn.val, info->vaddr, true);

	return 0;
}

static int t32_b1110_100x_x1(thumb_insn_t insn, struct decode_info *info)
{
	/* check PW bits */
	if (insn.hw1 & 0x120)
		return t32_ldrd_strd(insn, info);

	return thumb_not_implement(insn, info);
}

static int t32_b1110_100(thumb_insn_t insn, struct decode_info *info)
{
	if (GET_BIT(insn.hw1, 6))
		return t32_b1110_100x_x1(insn, info);

	return thumb_not_implement(insn, info);
}

static int b111(thumb_insn_t insn, struct decode_info *info)
{
	/* hw1[111x xxx? ???? ????] */
	switch (GET_FIELD(insn.hw1, 9, 4)) {
	case 0b0100:
		return t32_b1110_100(insn, info);
	}

	return thumb_not_implement(insn, info);
}


decode_handler_t table_xxx[8] = {
	/* 000 */	thumb_not_implement,
	/* 001 */	thumb_not_implement,
	/* 010 */	thumb_not_implement,
	/* 011 */	thumb_not_implement,
	/* 100 */	thumb_not_implement,
	/* 101 */	thumb_not_implement,
	/* 110 */	thumb_not_implement,
	/* 111 */	b111,
};


int decode_thumb(unsigned long insn, struct decode_info *info)
{
	thumb_insn_t tinsn = { .val = insn };

	/* check first 3 bits hw1[xxx? ???? ???? ????] */
	return table_xxx[GET_FIELD(tinsn.hw1, 13, 3)](tinsn, info);
}
