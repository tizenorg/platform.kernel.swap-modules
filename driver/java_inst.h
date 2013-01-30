#ifndef __JAVA_INST__
#define __JAVA_INST__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/java_inst.h
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
 * 2013         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */

struct pt_regs;
struct sspt_procs;

#ifdef __ANDROID

extern struct dentry *libdvm_dentry;
/* Defines below are for libdvm.so with md5sum:
 * 5941c87b49198368e7db726c2977bf1d */
#define LIBDVM_ENTRY 0x30a64
#define LIBDVM_RETURN 0x30bdc

void add_java_inst(struct sspt_procs *procs);
int handle_java_event(struct pt_regs *regs);

#else /* __ANDROID */

static inline void add_java_inst(struct sspt_procs *procs)
{
}

static inline int handle_java_event(struct pt_regs *regs)
{
	return 0;
}

#endif /* __ANDROID */

#endif /* __JAVA_INST__ */
