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

#include "../buffer/swap_buffer_module.h"
#include "../buffer/swap_buffer_errors.h"

#include "swap_writer_module.h"
#include "swap_writer_errors.h"
#include "kernel_operations.h"


enum MSG_ID {
	MSG_PROC_INFO			= 0x2002,
	MSG_ERROR			= 0x2005,
	MSG_SAMPLE			= 0x2006,
	MSG_FUNCTION_ENTRY		= 0x2010,
	MSG_FUNCTION_EXIT		= 0x2011,
	MSG_CONTEXT_SWITCH_ENTRY	= 0x2012,
	MSG_CONTEXT_SWITCH_EXIT		= 0x2013
};

static char *cpu_buf[NR_CPUS];
static u32 seq_num = 0;
static u64 discarded = 0;

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

static char *get_current_buf(void)
{
	return cpu_buf[task_cpu(current)];
}

static inline u64 timespec2time(struct timespec *ts)
{
	return ((u64)ts->tv_sec) << 32 | ts->tv_nsec;
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

static void write_to_buffer(void *data, size_t size)
{
	int result;

	result = swap_buffer_write(data, size);
	if (result != E_SB_SUCCESS) {
		discarded++;
	}
}

static void set_len_msg(char *buf, char *end)
{
	struct basic_msg_fmt *bmf = (struct basic_msg_fmt *)buf;
	bmf->len = end - buf - sizeof(*bmf);

	write_to_buffer(bmf->len + sizeof(*bmf), buf);
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
	u64 start_time;
	u64 low_addr;
	u64 high_addr;
	u32 app_type;
	u32 bin_type;
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
	struct file *file;

	lo->low_addr = vma->vm_start;
	lo->high_addr = vma->vm_end;

	return pack_path(lo->lib_path, vma->vm_file);
}

/* FIXME: check_vma()*/
static int check_vma(struct vm_area_struct *vma)
{
	return vma->vm_file && !(vma->vm_pgoff != 0 || !(vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_ACCOUNT) ||
			!(vma->vm_flags & (VM_WRITE | VM_MAYWRITE)) ||
			!(vma->vm_flags & (VM_READ | VM_MAYREAD)));
}

static char *pack_proc_info_part(char *bin_path, struct mm_struct *mm)
{
	struct proc_info_part *pip;
	struct vm_area_struct *vma;
	char *lib_obj, *end_path = NULL;
	int lib_cnt = 0;

	end_path = pack_path(bin_path, mm->exe_file);

	pip = (struct proc_info_part *)end_path;
	lib_obj = pip->libs;

	down_write(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma)) {
			lib_obj = pack_lib_obj(lib_obj, vma);
			++lib_cnt;
		}
	}
	up_write(&mm->mmap_sem);

	pip->lib_cnt = lib_cnt;
	return lib_obj;
}

static char *pack_proc_info(char *payload, struct task_struct *task)
{
	struct proc_info *pi = (struct proc_info *)payload;

	pi->pid = task->tgid;

	/* FIXME: */
	pi->start_time = timespec2time(&task->start_time);
	pi->low_addr = 2;
	pi->high_addr = 3;
	pi->app_type = 4;
	pi->bin_type = 5;

	return pack_proc_info_part(pi->bin_path, task->mm);
}

void proc_info_msg(struct task_struct *task)
{
	char *buf, *payload, *buf_end;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_PROC_INFO);
	buf_end = pack_proc_info(payload, task);

	set_len_msg(buf, buf_end);
}
EXPORT_SYMBOL_GPL(proc_info_msg);




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
	s->cpu_num = task_cpu(current);

	return payload + sizeof(*s);
}

void sample_msg(struct pt_regs *regs)
{
	char *buf, *payload, *buf_end;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_SAMPLE);
	buf_end = pack_sample(payload, regs);

	set_len_msg(buf, buf_end);
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

static char *pack_msg_func_entry(char *payload, const char *fmt, struct pt_regs *regs,
				 enum PROBE_TYPE pt, enum PROBE_SUB_TYPE pst)
{
	struct msg_func_entry *mfe = (struct msg_func_entry *)payload;
	struct task_struct *task = current;

	mfe->pid = task->tgid;
	mfe->tid = task->pid;
	mfe->cpu_num = task_cpu(task);
	mfe->pc_addr = get_regs_ip(regs);
//TODO ret address for x86!
	mfe->caller_pc_addr = get_regs_ret_func(regs);
	mfe->probe_type = pt;
	mfe->probe_sub_type = pst;
	mfe->cnt_args = strlen(fmt);

	return payload + sizeof(*mfe);
}

static int get_args(unsigned long args[], int cnt, struct pt_regs *regs)
{
	int i, arg_in_regs;

	arg_in_regs = cnt < 3 ? cnt : 3;
	switch (arg_in_regs) {
	case 3:
//TODO x86
		args[3] = get_regs_r3(regs);
	case 2:
//TODO x86
		args[2] = get_regs_r2(regs);
	case 1:
//TODO x86
		args[1] = get_regs_r1(regs);
	case 0:
//TODO x86
		args[0] = get_regs_r0(regs);
	}

	/* FIXME: cnt > 4 */
	for (i = 4; i < cnt; ++i) {
		args[i] = 0;
	}

	return 0;
}

static int pack_args(char *buf, int len, const char *fmt, struct pt_regs *regs)
{
	enum { args_cnt = 16 };
	char *buf_old = buf;
	unsigned long arg, args[args_cnt];
	u32 *tmp_u32;
	u64 *tmp_u64;
	int i, cnt;

	cnt = strlen(fmt);

	/* FIXME: when the number of arguments is greater than args_cnt */
	cnt = cnt < args_cnt ? cnt : args_cnt;
	get_args(args, cnt, regs);

	for (i = 0; i < cnt; ++i) {
		if (len < 2)
			return -ENOMEM;

		arg = args[i];
		*buf = fmt[i];
		buf += 1;
		len -= 1;

		switch (fmt[i]) {
		case 'c': /* 1 byte(char) */
			if (len < 1)
				return -ENOMEM;
			*buf = (char)arg;
			buf += 1;
			len -= 1;
			break;

		case 'd': /* 4 byte(int) */
			if (len < 4)
				return -ENOMEM;
			tmp_u32 = buf;
			*tmp_u32 = arg;
			buf += 4;
			len -= 4;
			break;

		case 'x': /* 8 byte(long) */
		case 'p': /* 8 byte(pointer) */
			if (len < 8)
				return -ENOMEM;
			tmp_u64 = buf;
			*tmp_u64 = (u64)arg;
			buf += 8;
			len -= 8;
			break;
//		case 'f': /* 4 byte(float) */
//			break;
//		case 'w': /* 8 byte(double) */
//			break;
		case 's': /* string end with '\0' */
		{
			enum { max_str_len = 512 };
			const char __user *user_s;
			int len_s, ret;

			user_s = (const char __user *)arg;
			len_s = strnlen_user(user_s, max_str_len);
			if (len < len_s)
				return -ENOMEM;

			ret = strncpy_from_user(buf, user_s, len_s);
			if (ret < 0)
				return -EFAULT;

			buf += ret;
			len -= ret;
		}
			break;
		default:
			return -EINVAL;
		}
	}

	return buf - buf_old;
}

void entry_event(const char *fmt, struct pt_regs *regs,
		 enum PROBE_TYPE pt, enum PROBE_SUB_TYPE pst)
{
	char *buf, *payload, *args, *buf_end;
	int ret;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_FUNCTION_ENTRY);
	args = pack_msg_func_entry(payload, fmt, regs, pt, pst);

	/* FIXME: len = 1024 */
	ret = pack_args(args, 1024, fmt, regs);
	if (ret < 0) {
		printk("ERROR: !!!!!\n");
		return;
	}

	buf_end = args + ret;

	set_len_msg(buf, buf_end);
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
	u32 cpu_num;
	u64 ret_val;
} __attribute__((packed));

static char *pack_msg_func_exit(char *payload, struct pt_regs *regs)
{
	struct msg_func_exit *mfe = (struct msg_func_exit *)payload;
	struct task_struct *task = current;

	mfe->pid = task->tgid;
	mfe->tid = task->pid;
	mfe->cpu_num = task_cpu(task);
	mfe->pc_addr = get_regs_ip(regs);
//TODO x86
	mfe->ret_val = get_regs_r0(regs);

	return payload + sizeof(*mfe);
}

void exit_event(struct pt_regs *regs)
{
	char *buf, *payload, *buf_end;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_FUNCTION_EXIT);
	buf_end = pack_msg_func_exit(payload, regs);
	set_len_msg(buf, buf_end);
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

	mcs->pc_addr = get_regs_ip(regs);
	mcs->pid = task->tgid;
	mcs->tid = task->pid;
	mcs->cpu_num = task_cpu(task);

	return payload + sizeof(*mcs);
}

static void context_switch(struct pt_regs *regs, enum MSG_ID id)
{
	char *buf, *payload, *buf_end;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, id);
	buf_end = pack_msg_context_switch(payload, regs);
	set_len_msg(buf, buf_end);
}

void switch_entry(struct pt_regs *regs)
{
	context_switch(regs, MSG_CONTEXT_SWITCH_ENTRY);
}
EXPORT_SYMBOL_GPL(switch_entry);

void switch_exit(struct pt_regs *regs)
{
	context_switch(regs, MSG_CONTEXT_SWITCH_EXIT);
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

void error_msg(const char *fmt, ...)
{
	char *buf, *payload, *buf_end;
	va_list args;

	buf = get_current_buf();
	payload = pack_basic_msg_fmt(buf, MSG_ERROR);

	va_start(args, fmt);
	buf_end = pack_msg_err(payload, fmt, args);
	va_end(args);

	set_len_msg(buf, buf_end);
}
EXPORT_SYMBOL_GPL(error_msg);

static int __init swap_writer_module_init(void)
{
	print_msg("SWAP Writer initialized\n");
}

static void __exit swap_writer_module_exit(void)
{
	print_msg("SWAP Writer uninitialized\n");
}

module_init(swap_writer_module_init);
module_exit(swap_writer_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP Writer module");
MODULE_AUTHOR("Cherkashin V., Aksenov A.S.");
