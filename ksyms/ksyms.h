#ifndef __KSYMS_H__
#define __KSYMS_H__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/ksyms/ksyms.h
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

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif

#include <linux/kallsyms.h>

#ifdef CONFIG_KALLSYMS

static inline int swap_get_ksyms(void)
{
	return 0;
}

static inline void swap_put_ksyms(void)
{
}

static inline unsigned long swap_ksyms(const char *name)
{
	return kallsyms_lookup_name(name);
}

#else /* !CONFIG_KALLSYMS */

int swap_get_ksyms(void);
void swap_put_ksyms(void);
unsigned long swap_ksyms(const char *name);

#endif /*CONFIG_KALLSYMS*/

#endif /*__KSYMS_H__*/
