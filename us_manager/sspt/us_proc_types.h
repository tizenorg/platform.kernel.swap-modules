#ifndef __US_PROC_TYPES_H__
#define __US_PROC_TYPES_H__

/*
 *  SWAP uprobe manager
 *  modules/us_manager/sspt/us_proc_types.h
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: Porting structures
 *              declarations from old driver
 *
 */

typedef struct
{
	struct list_head list;
	char *name;
	int installed;
	struct jprobe jprobe;
	struct kretprobe retprobe;
	unsigned long offset;
	unsigned long got_addr;

	unsigned flag_retprobe:1;
	unsigned flag_got:1;
} us_proc_ip_t;

typedef struct
{
	int installed;
	struct jprobe jprobe;
	unsigned long addr;
	struct list_head list;
} us_proc_vtp_t;

typedef struct
{
	unsigned func_addr;
	unsigned got_addr;
	unsigned real_func_addr;
} us_proc_plt_t;

typedef struct
{
	char *path;
	char *path_dyn;
	struct dentry *m_f_dentry;
	unsigned ips_count;
	us_proc_ip_t *p_ips;
	unsigned vtps_count;
	us_proc_vtp_t *p_vtps;
	int loaded;
	unsigned plt_count;
	us_proc_plt_t *p_plt;
	unsigned long vma_start;
	unsigned long vma_end;
	unsigned vma_flag;
} us_proc_lib_t;

typedef struct {
	char *path;
	struct dentry *m_f_dentry;
	pid_t tgid;
	unsigned unres_ips_count;
	unsigned unres_vtps_count;
	int is_plt;
	unsigned libs_count;
	us_proc_lib_t *p_libs;

	// new_dpf
	struct sspt_proc *pp;
} inst_us_proc_t;

#endif /* __US_PROC_TYPES_H__ */
