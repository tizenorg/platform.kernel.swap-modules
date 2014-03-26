/*
 *  SWAP Writer
 *  modules/writer/swap_writer_module.c
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

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <kprobe/arch/asm/dbi_kprobes.h>
#include <uprobe/arch/asm/swap_uprobes.h>

#include <buffer/swap_buffer_module.h>
#include <buffer/swap_buffer_errors.h>

#include "swap_writer_module.h"
#include "swap_writer_errors.h"
#include "kernel_operations.h"
#include "debugfs_writer.h"
#include "event_filter.h"


enum MSG_ID {
	MSG_PROC_INFO			= 0x0001,
	MSG_TERMINATE			= 0x0002,
	MSG_ERROR			= 0x0003,
	MSG_SAMPLE			= 0x0004,
	MSG_FUNCTION_ENTRY		= 0x0008,
	MSG_FUNCTION_EXIT		= 0x0009,
	MSG_CONTEXT_SWITCH_ENTRY	= 0x0010,
	MSG_CONTEXT_SWITCH_EXIT		= 0x0011,
	MSG_PROC_MAP			= 0x0012,
	MSG_PROC_UNMAP			= 0x0013
};

static char *cpu_buf[NR_CPUS];
static u32 seq_num = 0;
static unsigned int discarded = 0;

int init_msg(size_t buf_size)
{
	int i;

	for (i = 0; i < NR_CPUS; ++i)
		cpu_buf[i] = kmalloc(buf_size, GFP_KERNEL);

	return E_SW_SUCCESS;
}
EXPORT_SYMBOL_GPL(init_msg);

void uninit_msg(void)
{
	int i;

	for (i = 0; i < NR_CPUS; ++i)
		kfree(cpu_buf[i]);
}
EXPORT_SYMBOL_GPL(uninit_msg);

void reset_discarded(void)
{
	discarded = 0;
}
EXPORT_SYMBOL_GPL(reset_discarded);

void reset_seq_num(void)
{
	seq_num = 0;
}
EXPORT_SYMBOL_GPL(reset_seq_num);

unsigned int get_discarded_count(void)
{
	return discarded;
}
EXPORT_SYMBOL_GPL(get_discarded_count);

static inline char *get_current_buf(void)
{
	return cpu_buf[get_cpu()];
}

static inline void put_current_buf(void)
{
	put_cpu();
}

static inline u64 timespec2time(struct timespec *ts)
{
	return ((u64)ts->tv_nsec) << 32 | ts->tv_sec;
}

/* ============================================================================
 * =                         BASIC MESSAGE FORMAT                             =
 * ============================================================================
 */

struct basic_msg_fmt {
	u32 msg_id;
	u32 seq_number;
	u64 time;
	u32 len;
	char payload[0];
} __attribute__((packed));

#if 0 /* debug */
static void print_hex(char *ptr, int len)
{
	int i;

	printk("print_hex:\n");
	for (i = 0; i < len; ++i) {
		printk("[%x]  [%3d]=%2x\n", &ptr[i], i, ptr[i]);
	}
}
#endif

static int write_to_buffer(void *data)
{
	int result;
	struct basic_msg_fmt *bmf = (struct basic_msg_fmt *)data;

	result = swap_buffer_write(bmf, bmf->len + sizeof(*bmf));
	if (result < 0) {
		discarded++;
	}

	return result;
}

static void set_len_msg(char *buf, char *end)
{
	struct basic_msg_fmt *bmf = (struct basic_msg_fmt *)buf;
	bmf->len = end - buf - sizeof(*bmf);
}

static inline void set_seq_num(struct basic_msg_fmt *bmf)
{
	bmf->seq_number = seq_num;
	seq_num++;
}

static inline void set_time(struct basic_msg_fmt *bmf)
{
	struct timespec ts;

	getnstimeofday(&ts);
	bmf->time = timespec2time(&ts);
}

static char* pack_basic_msg_fmt(char *buf, enum MSG_ID id)
{
	struct basic_msg_fmt *bmf = (struct basic_msg_fmt *)buf;

	set_time(bmf);
	set_seq_num(bmf);
	bmf->msg_id = id;

	return bmf->payload;
}





/* ============================================================================
 * =                             PROCESS INFO                                 =
 * ============================================================================
 */

struct proc_info {
	u32 pid;
	u32 ppid;
	u32 start_sec;
	u32 start_nsec;
	u64 low_addr;
	u64 high_addr;
	char bin_path[0];
} __attribute__((packed));

struct proc_info_part {
	u32 lib_cnt;
	char libs[0];
} __attribute__((packed));

struct lib_obj {
	u64 low_addr;
	u64 high_addr;
	char lib_path[0];
} __attribute__((packed));

static char *pack_path(char *buf, struct file *file)
{
	enum { TMP_BUF_LEN = 512 };
	char tmp_buf[TMP_BUF_LEN];
	char NA[] = "N/A";
	char *filename;
	size_t len;

	if (file == NULL)
		return strcpy(buf, NA) + sizeof(NA);

	filename = d_path(&file->f_path, tmp_buf, TMP_BUF_LEN);
	if (IS_ERR_OR_NULL(filename))
		return strcpy(buf, NA) + sizeof(NA);

	len = strlen(filename) + 1;
	memcpy(buf, filename, len);

	return buf + len;
}

static char *pack_lib_obj(char *lib_obj, struct vm_area_struct *vma)
{
	struct lib_obj *lo = (struct lib_obj *)lib_obj;

	lo->low_addr = vma->vm_start;
	lo->high_addr = vma->vm_end;

	return pack_path(lo->lib_path, vma->vm_file);
}

/* FIXME: check_vma()*/
static int check_vma(struct vm_area_struct *vma)
{
	return vma->vm_file &&
	       !(vma->vm_pgoff != 0 ||
		 !(vma->vm_flags & VM_EXEC) ||
		 !(vma->vm_flags & (VM_READ | VM_MAYREAD)));
}

static struct vm_area_struct *find_vma_exe_by_dentry(struct mm_struct *mm, struct dentry *dentry)
{
	struct vm_area_struct *vma;

	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_file && (vma->vm_flags & VM_EXEC) &&
		   (vma->vm_file->f_dentry == dentry))
			goto out;
	}

	vma = NULL;
out:
	up_read(&mm->mmap_sem);

	return vma;
}

static char *pack_shared_kmem(char *lib_obj, struct mm_struct *mm,
                              u32 *lib_cnt_p)
{
	struct lib_obj *so = (struct lib_obj *)lib_obj;
	char *so_obj;
	unsigned long start = 0, end = 0;

	const char *kmem_name = get_shared_kmem(mm, &start, &end);
	size_t name_len;

	if (kmem_name == NULL)
		return lib_obj;

	name_len = strlen(kmem_name) + 1;
	so->low_addr = (u64)start;
	so->high_addr = (u64)end;
	memcpy(so->lib_path, kmem_name, name_len);
	(*lib_cnt_p)++;
	so_obj = so->lib_path + name_len;

	return so_obj;
}

static char *pack_libs(char *lib_obj, struct mm_struct *mm, u32 *lib_cnt_p)
{
	struct vm_area_struct *vma;

	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma)) {
			lib_obj = pack_lib_obj(lib_obj, vma);
			++(*lib_cnt_p);
		}
	}
	up_read(&mm->mmap_sem);

	return lib_obj;
}

static char *pack_proc_info_part(char *end_path, struct mm_struct *mm)
{
	struct proc_info_part *pip;
	char *lib_obj;
	u32 *lib_cnt_p;

	pip = (struct proc_info_part *)end_path;
	pip->lib_cnt = 0;
	lib_obj = pip->libs;
	lib_cnt_p = &pip->lib_cnt;

	lib_obj = pack_libs(lib_obj, mm, lib_cnt_p);
	lib_obj = pack_shared_kmem(lib_obj, mm, lib_cnt_p);

	return lib_obj;
}

static char *pack_proc_info(char *payload, struct task_struct *task,
			    struct dentry *dentry)
{
	struct proc_info *pi = (struct proc_info *)payload;
	struct vm_area_struct *vma = find_vma_exe_by_dentry(task->mm, dentry);
	struct timespec boot_time;
	struct timespec start_time;
	char *end_path = NULL;

	getboottime(&boot_time);
	start_time = timespec_add(boot_time, task->real_start_time);

	pi->pid = task->tgid;
	pi->ppid = task->real_parent->tgid;
	pi->start_sec = (u32)start_time.tv_sec;
	pi->start_nsec = (u32)start_time.tv_nsec;

	if (vma) {
		pi->low_addr = vma->vm_start;
		pi->high_addr = vma->vm_end;
		end_path = pack_path(pi->bin_path, vma->vm_file);
	} else {
		pi->low_addr = 0;
		pi->high_addr = 0;
		end_path = pack_path(pi->bin_path, NULL);
	}
	return pack_proc_info_part(end_path, task->mm);
}

int proc_info_msg(struct task_struct *task, struct dentry *dentry)
{
	char *buf, *payload, *buf_end;
	int ret;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_PROC_INFO);
	buf_end = pack_proc_info(payload, task, dentry);

	set_len_msg(buf, buf_end);

	ret = write_to_buffer(buf);
	put_current_buf();

	return ret;
}
EXPORT_SYMBOL_GPL(proc_info_msg);





/* ============================================================================
 * =                           PROCESS TERMINATE                              =
 * ============================================================================
 */

struct proc_terminate {
	u32 pid;
} __attribute__((packed));

static char *pack_proc_terminate(char *payload, struct task_struct *task)
{
	struct proc_terminate *pt = (struct proc_terminate *)payload;

	pt->pid = task->pid;
	return payload + sizeof(*pt);
}

void terminate_msg(struct task_struct *task)
{
	char *buf, *payload, *buf_end;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_TERMINATE);
	buf_end = pack_proc_terminate(payload, task);

	set_len_msg(buf, buf_end);

	write_to_buffer(buf);
	put_current_buf();
}
EXPORT_SYMBOL_GPL(terminate_msg);





/* ============================================================================
 * =                             PROCESS MAP                                  =
 * ============================================================================
 */
struct proc_map {
	u32 pid;
	u64 low_addr;
	u64 high_addr;
	char bin_path[0];
} __attribute__((packed));

static char *pack_proc_map(char *payload, struct vm_area_struct *vma)
{
	struct proc_map *pm = (struct proc_map *)payload;

	pm->pid = current->tgid;
	pm->low_addr = vma->vm_start;
	pm->high_addr = vma->vm_end;

	return pack_path(pm->bin_path, vma->vm_file);
}

void pcoc_map_msg(struct vm_area_struct *vma)
{
	char *buf, *payload, *buf_end;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_PROC_MAP);
	buf_end = pack_proc_map(payload, vma);

	set_len_msg(buf, buf_end);

	write_to_buffer(buf);
	put_current_buf();
}
EXPORT_SYMBOL_GPL(pcoc_map_msg);





/* ============================================================================
 * =                            PROCESS UNMAP                                 =
 * ============================================================================
 */
struct proc_unmap {
	u32 pid;
	u64 low_addr;
	u64 high_addr;
} __attribute__((packed));

static char *pack_proc_unmap(char *payload, unsigned long start,
			     unsigned long end)
{
	struct proc_unmap *pum = (struct proc_unmap *)payload;

	pum->pid = current->tgid;
	pum->low_addr = start;
	pum->high_addr = end;

	return payload + sizeof(*pum);
}

void proc_unmap_msg(unsigned long start, unsigned long end)
{
	char *buf, *payload, *buf_end;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_PROC_UNMAP);
	buf_end = pack_proc_unmap(payload, start, end);

	set_len_msg(buf, buf_end);

	write_to_buffer(buf);
	put_current_buf();
}
EXPORT_SYMBOL_GPL(proc_unmap_msg);





/* ============================================================================
 * =                                 SAMPLE                                   =
 * ============================================================================
 */

struct sample {
	u32 pid;
	u64 pc_addr;
	u32 tid;
	u32 cpu_num;
} __attribute__((packed));

static char *pack_sample(char *payload, struct pt_regs *regs)
{
	struct sample *s = (struct sample *)payload;
	struct task_struct *task = current;

	s->pid = task->tgid;
	s->pc_addr = get_regs_ip(regs);
	s->tid = task->pid;
	s->cpu_num = smp_processor_id();

	return payload + sizeof(*s);
}

int sample_msg(struct pt_regs *regs)
{
	char *buf, *payload, *buf_end;
	int ret;

	if (!check_event(current))
		return 0;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_SAMPLE);
	buf_end = pack_sample(payload, regs);

	set_len_msg(buf, buf_end);

	ret = write_to_buffer(buf);
	put_current_buf();

	return ret;
}
EXPORT_SYMBOL_GPL(sample_msg);




/* ============================================================================
 * =                                 ENTRY                                    =
 * ============================================================================
 */

struct msg_func_entry {
	u64 pc_addr;
	u64 caller_pc_addr;
	u16 probe_type;
	u16 probe_sub_type;
	u32 pid;
	u32 tid;
	u32 cpu_num;
	u32 cnt_args;
	char args[0];
} __attribute__((packed));

static char *pack_msg_func_entry(char *payload, const char *fmt,
				 unsigned long func_addr, struct pt_regs *regs,
				 enum PROBE_TYPE pt, int sub_type)
{
	struct msg_func_entry *mfe = (struct msg_func_entry *)payload;
	struct task_struct *task = current;

	mfe->pid = task->tgid;
	mfe->tid = task->pid;
	mfe->cpu_num = smp_processor_id();
	mfe->pc_addr = func_addr;
	mfe->caller_pc_addr = get_regs_ret_func(regs);
	mfe->probe_type = pt;
	mfe->probe_sub_type = sub_type;
	mfe->cnt_args = strlen(fmt);

	return payload + sizeof(*mfe);
}

static unsigned long get_arg(struct pt_regs *regs, unsigned long n)
{
	return user_mode(regs) ?
			swap_get_uarg(regs, n) :	/* US argument */
			swap_get_sarg(regs, n);		/* sys_call argument */
}

static int pack_args(char *buf, int len, const char *fmt, struct pt_regs *regs)
{
	char *buf_old = buf;
	u32 *tmp_u32;
	u64 *tmp_u64;
	int i,		/* the index of the argument */
	    fmt_i,	/* format index */
	    fmt_len;	/* the number of parameters, in format */

	fmt_len = strlen(fmt);

	for (i = 0, fmt_i = 0; fmt_i < fmt_len; ++i, ++fmt_i) {
		if (len < 2)
			return -ENOMEM;

		*buf = fmt[fmt_i];
		buf += 1;
		len -= 1;

		switch (fmt[fmt_i]) {
		case 'b': /* 1 byte(bool) */
			*buf = (char)!!get_arg(regs, i);
			buf += 1;
			len -= 1;
			break;
		case 'c': /* 1 byte(char) */
			*buf = (char)get_arg(regs, i);
			buf += 1;
			len -= 1;
			break;
		case 'f': /* 4 byte(float) */
		case 'd': /* 4 byte(int) */
			if (len < 4)
				return -ENOMEM;
			tmp_u32 = (u32 *)buf;
			*tmp_u32 = (u32)get_arg(regs, i);
			buf += 4;
			len -= 4;
			break;
		case 'x': /* 8 byte(long) */
		case 'p': /* 8 byte(pointer) */
			if (len < 8)
				return -ENOMEM;
			tmp_u64 = (u64 *)buf;
			*tmp_u64 = (u64)get_arg(regs, i);
			buf += 8;
			len -= 8;
			break;
		case 'w': /* 8 byte(double) */
			if (len < 8)
				return -ENOMEM;
			tmp_u64 = (u64 *)buf;
			*tmp_u64 = get_arg(regs, i);
			++i;
			*tmp_u64 |= (u64)get_arg(regs, i) << 32;
			buf += 8;
			len -= 8;
			break;
		case 's': /* string end with '\0' */
		{
			enum { max_str_len = 512 };
			const char __user *user_s;
			int len_s, ret;

			user_s = (const char __user *)get_arg(regs, i);
			len_s = strnlen_user(user_s, max_str_len);
			if (len < len_s)
				return -ENOMEM;

			ret = strncpy_from_user(buf, user_s, len_s);
			if (ret < 0)
				return -EFAULT;

			buf[ret] = '\0';

			buf += ret + 1;
			len -= ret + 1;
		}
			break;
		default:
			return -EINVAL;
		}
	}

	return buf - buf_old;
}

int entry_event(const char *fmt, unsigned long func_addr, struct pt_regs *regs,
		enum PROBE_TYPE pt, int sub_type)
{
	char *buf, *payload, *args, *buf_end;
	int ret;

	if (pt == PT_KS && !check_event(current))
		return 0;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_FUNCTION_ENTRY);
	args = pack_msg_func_entry(payload, fmt, func_addr,
				   regs, pt, sub_type);

	/* FIXME: len = 1024 */
	ret = pack_args(args, 1024, fmt, regs);
	if (ret < 0) {
		printk("ERROR: !!!!!\n");
		return ret;
	}

	buf_end = args + ret;

	set_len_msg(buf, buf_end);

	ret = write_to_buffer(buf);
	put_current_buf();

	return ret;
}
EXPORT_SYMBOL_GPL(entry_event);





/* ============================================================================
 * =                                 EXIT                                     =
 * ============================================================================
 */

struct msg_func_exit {
	u32 pid;
	u32 tid;
	u64 pc_addr;
	u64 caller_pc_addr;
	u32 cpu_num;
	char ret_val[0];
} __attribute__((packed));

static int pack_msg_ret_val(char *buf, int len, char ret_type,
			      struct pt_regs *regs)
{
	const char *buf_old = buf;
	u32 *tmp_u32;
	u64 *tmp_u64;

	*buf = ret_type;
	++buf;

	switch (ret_type) {
	case 'b': /* 1 byte(bool) */
		if (len < 1)
			return -ENOMEM;
		*buf = (char)!!get_regs_ret_val(regs);
		++buf;
		break;
	case 'c': /* 1 byte(char) */
		if (len < 1)
			return -ENOMEM;
		*buf = (char)get_regs_ret_val(regs);
		++buf;
		break;
	case 'd': /* 4 byte(int) */
		if (len < 4)
			return -ENOMEM;
		tmp_u32 = (u32 *)buf;
		*tmp_u32 = get_regs_ret_val(regs);
		buf += 4;
		break;
	case 'x': /* 8 byte(long) */
	case 'p': /* 8 byte(pointer) */
		if (len < 8)
			return -ENOMEM;
		tmp_u64 = (u64 *)buf;
		*tmp_u64 = (u64)get_regs_ret_val(regs);
		buf += 8;
		break;
	case 's': /* string end with '\0' */
	{
		enum { max_str_len = 512 };
		const char __user *user_s;
		int len_s, ret;

		user_s = (const char __user *)get_regs_ret_val(regs);
		len_s = strnlen_user(user_s, max_str_len);
		if (len < len_s)
			return -ENOMEM;

		ret = strncpy_from_user(buf, user_s, len_s);
		if (ret < 0)
			return -EFAULT;

		buf[ret] = '\0';
		buf += ret + 1;
	}
		break;
	case 'n':
	case 'v':
		break;
	case 'f': /* 4 byte(float) */
		if (len < 4)
			return -ENOMEM;
		tmp_u32 = (u32 *)buf;
		*tmp_u32 = swap_get_urp_float(regs);
		buf += 4;
		break;
	case 'w': /* 8 byte(double) */
		if (len < 8)
			return -ENOMEM;
		tmp_u64 = (u64 *)buf;
		*tmp_u64 = swap_get_urp_double(regs);
		buf += 8;
		break;
	default:
		return -EINVAL;
	}

	return buf - buf_old;
}


static int pack_msg_func_exit(char *buf, int len, char ret_type,
			      struct pt_regs *regs, unsigned long func_addr,
			      unsigned long ret_addr)
{
	struct msg_func_exit *mfe = (struct msg_func_exit *)buf;
	struct task_struct *task = current;
	int ret;

	mfe->pid = task->tgid;
	mfe->tid = task->pid;
	mfe->cpu_num = smp_processor_id();
	mfe->pc_addr = func_addr;
	mfe->caller_pc_addr = ret_addr;

	ret = pack_msg_ret_val(mfe->ret_val, len, ret_type, regs);
	if (ret < 0) {
		printk("ERROR: packing MSG_FUNCTION_EXIT (ret=%d)\n", ret);
		return ret;
	}

	return sizeof(*mfe) + ret;
}

int exit_event(char ret_type, struct pt_regs *regs, unsigned long func_addr,
	       unsigned long ret_addr)
{
	char *buf, *payload, *buf_end;
	int ret;

	if (!check_event(current))
		return 0;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_FUNCTION_EXIT);
	/* FIXME: len=1024 */
	ret = pack_msg_func_exit(payload, 1024, ret_type, regs,
				 func_addr, ret_addr);
	if (ret < 0)
		return ret;

	buf_end = payload + ret;
	set_len_msg(buf, buf_end);

	ret = write_to_buffer(buf);
	put_current_buf();

	return ret;
}
EXPORT_SYMBOL_GPL(exit_event);





/* ============================================================================
 * =                            CONTEXT SWITCH                                =
 * ============================================================================
 */

struct msg_context_switch {
	u64 pc_addr;
	u32 pid;
	u32 tid;
	u32 cpu_num;
} __attribute__((packed));

static char *pack_msg_context_switch(char *payload, struct pt_regs *regs)
{
	struct msg_context_switch *mcs = (struct msg_context_switch *)payload;
	struct task_struct *task = current;

	mcs->pc_addr = 0;
	mcs->pid = task->tgid;
	mcs->tid = task->pid;
	mcs->cpu_num = smp_processor_id();

	return payload + sizeof(*mcs);
}

static int context_switch(struct pt_regs *regs, enum MSG_ID id)
{
	char *buf, *payload, *buf_end;
	int ret;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, id);
	buf_end = pack_msg_context_switch(payload, regs);
	set_len_msg(buf, buf_end);

	ret = write_to_buffer(buf);
	put_current_buf();

	return ret;
}

int switch_entry(struct pt_regs *regs)
{
	if (!check_event(current))
		return 0;

	return context_switch(regs, MSG_CONTEXT_SWITCH_ENTRY);
}
EXPORT_SYMBOL_GPL(switch_entry);

int switch_exit(struct pt_regs *regs)
{
	if (!check_event(current))
		return 0;

	return context_switch(regs, MSG_CONTEXT_SWITCH_EXIT);
}
EXPORT_SYMBOL_GPL(switch_exit);




/* ============================================================================
 * =                                 ERROR                                    =
 * ============================================================================
 */

struct msg_err {
	char msg[0];
} __attribute__((packed));

static char *pack_msg_err(char *payload, const char *fmt, va_list args)
{
	struct msg_err *me = (struct msg_err *)payload;
	int ret;

	ret = vsprintf(me->msg, fmt, args);
	if (ret < 0)
		return payload;

	return payload + sizeof(*me) + ret + 1;
}

int error_msg(const char *fmt, ...)
{
	char *buf, *payload, *buf_end;
	va_list args;
	int ret;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_ERROR);

	va_start(args, fmt);
	buf_end = pack_msg_err(payload, fmt, args);
	va_end(args);

	set_len_msg(buf, buf_end);

	ret = write_to_buffer(buf);
	put_current_buf();

	return ret;
}
EXPORT_SYMBOL_GPL(error_msg);





/* ============================================================================
 * =                         MESSAGES FROM USER SPACE                         =
 * ============================================================================
 */

int raw_msg(char *buf, size_t len)
{
	struct basic_msg_fmt *bmf = (struct basic_msg_fmt *)buf;

	if (sizeof(*bmf) > len)
		return -EINVAL;

	if (bmf->len + sizeof(*bmf) != len)
		return -EINVAL;

	set_seq_num(bmf);
	write_to_buffer(buf);

	return len;
}

static int __init swap_writer_module_init(void)
{
	int ret;

	ret = event_filter_init();
	if (ret)
		return ret;

	ret = init_debugfs_writer();
	if (ret)
		event_filter_exit();

	return ret;
}

static void __exit swap_writer_module_exit(void)
{
	exit_debugfs_writer();
	event_filter_exit();
}

module_init(swap_writer_module_init);
module_exit(swap_writer_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP Writer module");
MODULE_AUTHOR("Cherkashin V., Aksenov A.S.");
