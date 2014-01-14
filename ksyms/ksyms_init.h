/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/ksyms/ksyms_init.h
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
 * Copyright (C) Samsung Electronics, 2014
 *
 * 2014         Alexander Aksenov <a.aksenov@samsung.com>
 *
 */

#ifndef __KSYMS_INIT_H__
#define __KSYMS_INIT_H__

#ifdef CONFIG_KALLSYMS

static inline int ksyms_init(void)
{
	return 0;
}

static inline void ksyms_exit(void)
{
}

#else /* CONFIG_KALLSYMS */

int ksyms_init(void);
void ksyms_exit(void);

#endif /* CONFIG_KALLSYMS */

#endif /* __KSYMS_INIT_H__ */
