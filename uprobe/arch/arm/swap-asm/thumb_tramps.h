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


#ifndef _ARM_THUMB_TRAMPS_H
#define _ARM_THUMB_TRAMPS_H


#include <linux/types.h>


void tt_make_common(void *tramp, unsigned long insn,
		    unsigned long vaddr, bool t2);
void tt_make_pc_deps(void *tramp, unsigned long mod_insn,
		     unsigned long vaddr, bool t2);


#endif /* _ARM_THUMB_TRAMPS_H */
