#ifndef _KS_MANAGER_H
#define _KS_MANAGER_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/ks_manager/ks_manager.h
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

#include <dbi_kprobes.h>

struct kern_probe {
	struct jprobe jp;
	struct kretprobe rp;
};

int ksm_register_probe(unsigned long addr, void *pre_handler,
		       void *jp_handler, void *rp_handler);
int ksm_unregister_probe(unsigned long addr);

int ksm_unregister_probe_all(void);

#endif /* _KS_MANAGER_H */
