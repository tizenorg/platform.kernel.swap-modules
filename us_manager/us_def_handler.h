/*
 *  SWAP uprobe manager
 *  modules/us_manager/us_def_handler.h
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
 * 2013	 Vyacheslav Cherkashin: SWAP us_manager implement
 *
 */

#ifndef _US_DEF_HANDLER_H
#define _US_DEF_HANDLER_H

#include <asm/percpu.h>

struct us_ip;
struct pt_regs;
struct uretprobe_instance;

DECLARE_PER_CPU(struct us_ip *, gpCurIp);
DECLARE_PER_CPU(struct pt_regs *, gpUserRegs);

unsigned long ujprobe_event_pre_handler(struct us_ip *ip,
					struct pt_regs *regs);
void ujprobe_event_handler(unsigned long arg0, unsigned long arg1,
			   unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5);
int uretprobe_event_handler(struct uretprobe_instance *p,
			    struct pt_regs *regs);

#endif /* _US_DEF_HANDLER_H */
