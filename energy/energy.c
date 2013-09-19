/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/energy/swap_energy.c
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
 * 2013         Vasiliy Ulyanov <v.ulyanov@samsung.com>
 *              Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/module.h>
#include <linux/time.h>
#include <linux/file.h>
#include <linux/spinlock.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <kprobe/dbi_kprobes.h>
#include <ksyms/ksyms.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/sspt/sspt_feature.h>
#include "debugfs_energy.h"


struct energy_data {
	/* for __switch_to */
	u64 time[NR_CPUS];
	u64 time_tmp[NR_CPUS];

	/* for sys_read */
	u64 sys_read_byte;
	spinlock_t sys_read_lock;

	/*for sys_write */
	u64 sys_write_byte;
	spinlock_t sys_write_lock;
};

static sspt_feature_id_t feature_id = SSPT_FEATURE_ID_BAD;

static void *create_ed(void)
{
	struct energy_data *ed;

	ed = kmalloc(sizeof(*ed), GFP_ATOMIC);
	if (ed) {
		memset(ed, 0, sizeof(*ed));
		spin_lock_init(&ed->sys_read_lock);
		spin_lock_init(&ed->sys_write_lock);
	}

	return (void *)ed;
}

static void destroy_ed(void *data)
{
	struct energy_data *ed = (struct energy_data *)data;
	kfree(ed);
}


static int init_feature(void)
{
	feature_id = sspt_register_feature(create_ed, destroy_ed);

	if (feature_id == SSPT_FEATURE_ID_BAD)
		return -EPERM;

	return 0;
}

static void uninit_feature(void)
{
	sspt_unregister_feature(feature_id);
	feature_id = SSPT_FEATURE_ID_BAD;
}

static u64 get_ntime(void)
{
	struct timespec ts;

	getnstimeofday(&ts);

	return (u64)ts.tv_sec * 1000*1000*1000 + ts.tv_nsec;
}

static struct energy_data *get_energy_data(struct task_struct *task)
{
	void *data = NULL;
	struct sspt_proc *proc;

	proc = sspt_proc_get_by_task(task);
	if (proc)
		data = sspt_get_feature_data(proc->feature, feature_id);

	return (struct energy_data *)data;
}

static int check_fs(unsigned long magic)
{
	switch (magic) {
	case EXT2_SUPER_MAGIC: /* == EXT3_SUPER_MAGIC == EXT4_SUPER_MAGIC */
	case MSDOS_SUPER_MAGIC:
		return 1;
	}

	return 0;
}

static int check_ftype(int fd)
{
	int err, ret = 0;
	struct kstat kstat;

	err = vfs_fstat(fd, &kstat);
	if (err == 0 && S_ISREG(kstat.mode))
		ret = 1;

	return ret;
}

static unsigned long get_arg0(struct pt_regs *regs)
{
#if defined(CONFIG_ARM)
	return regs->ARM_r0;
#elif defined(CONFIG_X86_32)
	return regs->bx;
#else
	#error "this architecture is not supported"
#endif /* CONFIG_arch */
}





/* ============================================================================
 * =                             __switch_to                                  =
 * ============================================================================
 */
static int entry_handler_switch(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct energy_data *ed;

	ed = get_energy_data(current);
	if (ed) {
		int cpu = task_cpu(current);

		if (ed->time_tmp[cpu]) {
			ed->time[cpu] += get_ntime() - ed->time_tmp[cpu];
			ed->time_tmp[cpu] = 0;
		}
	}

	return 0;
}

static int ret_handler_switch(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct energy_data *ed;

	ed = get_energy_data(current);
	if (ed) {
		int cpu;

		cpu = task_cpu(current);
		ed->time_tmp[cpu] = get_ntime();
	}

	return 0;
}

static struct kretprobe switch_to_krp = {
	.entry_handler = entry_handler_switch,
	.handler = ret_handler_switch,
};





/* ============================================================================
 * =                                sys_read                                  =
 * ============================================================================
 */
struct sys_read_data {
	int fd;
};

static int entry_handler_sys_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sys_read_data *srd = (struct sys_read_data *)ri->data;

	srd->fd = (int)get_arg0(regs);

	return 0;
}

static struct energy_data *get_and_check_energy_data(int fd)
{
	struct energy_data *ed;
	ed = get_energy_data(current);
	if (ed) {
		struct file *file;

		file = fget(fd);
		if (file) {
			int magic = 0;
			if (file->f_dentry && file->f_dentry->d_sb)
				magic = file->f_dentry->d_sb->s_magic;

			fput(file);

			if (check_fs(magic) && check_ftype(fd))
				return ed;
		}
	}

	return NULL;
}

static int ret_handler_sys_read(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	int ret = regs_return_value(regs);

	if (ret > 0) {
		struct energy_data *ed;
		struct sys_read_data *srd;

		srd = (struct sys_read_data *)ri->data;
		ed = get_and_check_energy_data(srd->fd);

		if (ed) {
			spin_lock(&ed->sys_read_lock);
			ed->sys_read_byte += ret;
			spin_unlock(&ed->sys_read_lock);
		}
	}

	return 0;
}

static struct kretprobe sys_read_krp = {
	.entry_handler = entry_handler_sys_read,
	.handler = ret_handler_sys_read,
	.data_size = sizeof(struct sys_read_data)
};





/* ============================================================================
 * =                               sys_write                                  =
 * ============================================================================
 */
static int entry_handler_sys_write(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sys_read_data *srd = (struct sys_read_data *)ri->data;

	srd->fd = (int)get_arg0(regs);

	return 0;
}

static int ret_handler_sys_write(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret = regs_return_value(regs);

	if (ret > 0) {
		struct energy_data *ed;
		struct sys_read_data *srd;

		srd = (struct sys_read_data *)ri->data;
		ed = get_and_check_energy_data(srd->fd);
		if (ed) {
			spin_lock(&ed->sys_write_lock);
			ed->sys_write_byte += ret;
			spin_unlock(&ed->sys_write_lock);
		}
	}

	return 0;
}

static struct kretprobe sys_write_krp = {
	.entry_handler = entry_handler_sys_write,
	.handler = ret_handler_sys_write,
	.data_size = sizeof(struct sys_read_data)
};





int set_energy(void)
{
	int ret = 0;

	ret = dbi_register_kretprobe(&sys_read_krp);
	if (ret) {
		printk("dbi_register_kretprobe(sys_read) result=%d!\n", ret);
		return ret;
	}

	ret = dbi_register_kretprobe(&sys_write_krp);
	if (ret != 0) {
		printk("dbi_register_kretprobe(sys_write) result=%d!\n", ret);
		goto unregister_sys_read;
	}

	ret = dbi_register_kretprobe(&switch_to_krp);
	if (ret) {
		printk("dbi_register_kretprobe(__switch_to) result=%d!\n", ret);
		goto unregister_sys_write;
	}

	return ret;

unregister_sys_read:
	dbi_unregister_kretprobe(&sys_read_krp);

unregister_sys_write:
	dbi_unregister_kretprobe(&sys_write_krp);

	return ret;
}
EXPORT_SYMBOL_GPL(set_energy);

void unset_energy(void)
{
	dbi_unregister_kretprobe(&switch_to_krp);
	dbi_unregister_kretprobe(&sys_write_krp);
	dbi_unregister_kretprobe(&sys_read_krp);
}
EXPORT_SYMBOL_GPL(unset_energy);

static int __init swap_energy_init(void)
{
	int ret;
	unsigned long addr;

	ret = init_debugfs_energy();
	if (ret)
		return ret;

	addr = swap_ksyms("__switch_to");
	if (addr == 0) {
		printk("Cannot find address for __switch_to function!\n");
		return -EINVAL;
	}
	switch_to_krp.kp.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms("sys_read");
	if (addr == 0) {
		printk("Cannot find address for sys_read function!\n");
		return -EINVAL;
	}
	sys_read_krp.kp.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms("sys_write");
	if (addr == 0) {
		printk("Cannot find address for sys_write function!\n");
		return -EINVAL;
	}
	sys_write_krp.kp.addr = (kprobe_opcode_t *)addr;

	ret = init_feature();

	return ret;
}

static void __exit swap_energy_exit(void)
{
	uninit_feature();
	exit_debugfs_energy();
}

module_init(swap_energy_init);
module_exit(swap_energy_exit);

MODULE_LICENSE("GPL");
