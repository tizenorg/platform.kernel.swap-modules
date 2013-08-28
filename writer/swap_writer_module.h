/*
 *  SWAP Writer
 *  modules/writer/swap_writer_module.h
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>, Vyacheslav Cherkashin: 
 *                  SWAP Writer module implement
 *
 */

#ifndef _SWAP_MSG_H
#define _SWAP_MSG_H

#include <linux/types.h>

enum PROBE_TYPE {
	PT_US	= 1,
	PT_KS	= 3
};

enum PROBE_SUB_TYPE {
	PST_NONE	= 0x00,
	PST_KS_FILE	= 0x01,
	PST_KS_IPC	= 0x02,
	PST_KS_PROCESS	= 0x04,
	PST_KS_SIGNAL	= 0x08,
	PST_KS_NETWORK	= 0x10,
	PST_KS_DESC	= 0x20
};

struct pt_regs;

int init_msg(size_t buf_size);
void uninit_msg(void);

void reset_discarded(void);
unsigned int get_discarded_count(void);
void reset_seq_num(void);

int proc_info_msg(struct task_struct *task, void *priv);
int sample_msg(struct pt_regs *regs);

int entry_event(const char *fmt, struct pt_regs *regs,
		 enum PROBE_TYPE pt, int sub_type);
int exit_event(struct pt_regs *regs, unsigned long func_addr);

int switch_entry(struct pt_regs *regs);
int switch_exit(struct pt_regs *regs);

int error_msg(const char *fmt, ...);

int us_msg(void *us_message);

#endif /* _SWAP_MSG_H */
