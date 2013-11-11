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
#include <linux/atomic.h>
#include "energy.h"
#include "lcd/lcd_base.h"


static u64 get_ntime(void)
{
	struct timespec ts;
	getnstimeofday(&ts);
	return timespec_to_ns(&ts);
}





/* ============================================================================
 * =                              CPUS_TIME                                   =
 * ============================================================================
 */
struct cpus_time {
	u64 time_running[NR_CPUS];
	u64 time_entry[NR_CPUS];
};

static void cpus_time_init(struct cpus_time *ct, u64 time)
{
	int cpu;

	for (cpu = 0; cpu < NR_CPUS; ++cpu) {
		ct->time_running[cpu] = 0;
		ct->time_entry[cpu] = time;
	}
}

static u64 cpus_time_get_running_all(struct cpus_time *ct)
{
	u64 time = 0;
	int cpu;

	for (cpu = 0; cpu < NR_CPUS; ++cpu)
		time += ct->time_running[cpu];

	return time;
}

static void cpus_time_save_entry(struct cpus_time *ct, int cpu, u64 time)
{
	ct->time_entry[cpu] = time;
}

static void cpus_time_update_running(struct cpus_time *ct, int cpu, u64 time)
{
	ct->time_running[cpu] += time - ct->time_entry[cpu];
}





struct energy_data {
	/* for __switch_to */
	struct cpus_time ct;

	/* for sys_read */
	atomic64_t bytes_read;

	/*for sys_write */
	atomic64_t bytes_written;

};

static sspt_feature_id_t feature_id = SSPT_FEATURE_ID_BAD;

static void init_ed(struct energy_data *ed)
{
	cpus_time_init(&ed->ct, get_ntime());
	atomic64_set(&ed->bytes_read, 0);
	atomic64_set(&ed->bytes_written, 0);
}

static void uninit_ed(struct energy_data *ed)
{
	cpus_time_init(&ed->ct, 0);
	atomic64_set(&ed->bytes_read, 0);
	atomic64_set(&ed->bytes_written, 0);
}

static void *create_ed(void)
{
	struct energy_data *ed;

	ed = kmalloc(sizeof(*ed), GFP_ATOMIC);
	if (ed)
		init_ed(ed);

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

static int check_file(int fd)
{
	struct file *file;

	file = fget(fd);
	if (file) {
		int magic = 0;
		if (file->f_dentry && file->f_dentry->d_sb)
			magic = file->f_dentry->d_sb->s_magic;

		fput(file);

		if (check_fs(magic) && check_ftype(fd))
			return 1;
	}

	return 0;
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





static struct cpus_time ct_idle;
static struct energy_data ed_system;

static void init_data_energy(void)
{
	init_ed(&ed_system);
	cpus_time_init(&ct_idle, get_ntime());
}

static void uninit_data_energy(void)
{
	uninit_ed(&ed_system);
	cpus_time_init(&ct_idle, 0);
}





/* ============================================================================
 * =                             __switch_to                                  =
 * ============================================================================
 */
static int entry_handler_switch(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int cpu;
	u64 time;
	struct cpus_time* ct;
	struct energy_data *ed;

	cpu = smp_processor_id();
	time = get_ntime();
	ct = current->tgid ? &ed_system.ct : &ct_idle;
	cpus_time_update_running(ct, cpu, time);

	ed = get_energy_data(current);
	if (ed)
		cpus_time_update_running(&ed->ct, cpu, time);

	return 0;
}

static int ret_handler_switch(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int cpu;
	u64 time;
	struct cpus_time* ct;
	struct energy_data *ed;

	cpu = smp_processor_id();
	time = get_ntime();
	ct = current->tgid ? &ed_system.ct : &ct_idle;
	cpus_time_save_entry(ct, cpu, time);

	ed = get_energy_data(current);
	if (ed)
		cpus_time_save_entry(&ed->ct, cpu, time);

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

static int ret_handler_sys_read(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	int ret = regs_return_value(regs);

	if (ret > 0) {
		struct sys_read_data *srd;

		srd = (struct sys_read_data *)ri->data;
		if (check_file(srd->fd)) {
			struct energy_data *ed;

			ed = get_energy_data(current);
			if (ed)
				atomic64_add(ret, &ed->bytes_read);

			atomic64_add(ret, &ed_system.bytes_read);
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
		struct sys_read_data *srd;

		srd = (struct sys_read_data *)ri->data;
		if (check_file(srd->fd)) {
			struct energy_data *ed;

			ed = get_energy_data(current);
			if (ed)
				atomic64_add(ret, &ed->bytes_written);

			atomic64_add(ret, &ed_system.bytes_written);
		}
	}

	return 0;
}

static struct kretprobe sys_write_krp = {
	.entry_handler = entry_handler_sys_write,
	.handler = ret_handler_sys_write,
	.data_size = sizeof(struct sys_read_data)
};





enum parameter_type {
	PT_CPU,
	PT_READ,
	PT_WRITE
};

struct cmd_pt {
	enum parameter_type pt;
	u64 val;
};

static void callback_for_proc(struct sspt_proc *proc, void *data)
{
	void *f_data = sspt_get_feature_data(proc->feature, feature_id);
	struct energy_data *ed = (struct energy_data *)f_data;

	if (ed) {
		struct cmd_pt *cmdp = (struct cmd_pt *)data;

		switch (cmdp->pt) {
		case PT_CPU:
			cmdp->val += cpus_time_get_running_all(&ed->ct);
			break;
		case PT_READ:
			cmdp->val += atomic64_read(&ed->bytes_read);
			break;
		case PT_WRITE:
			cmdp->val += atomic64_read(&ed->bytes_written);
			break;
		default:
			break;
		}
	}
}

static u64 current_parameter_apps(enum parameter_type pt)
{
	struct cmd_pt cmdp;

	cmdp.pt = pt;
	cmdp.val = 0;

	on_each_proc(callback_for_proc, (void *)&cmdp);

	return cmdp.val;
}

u64 get_parameter_energy(enum parameter_energy pe)
{
	u64 val = 0;

	switch (pe) {
	case PE_TIME_IDLE:
		val = cpus_time_get_running_all(&ct_idle);
		break;
	case PE_TIME_SYSTEM:
		val = cpus_time_get_running_all(&ed_system.ct);
		break;
	case PE_TIME_APPS:
		val = current_parameter_apps(PT_CPU);
		break;
	case PE_READ_SYSTEM:
		val = atomic64_read(&ed_system.bytes_read);
		break;
	case PE_WRITE_SYSTEM:
		val = atomic64_read(&ed_system.bytes_written);
		break;
	case PE_READ_APPS:
		val = current_parameter_apps(PT_READ);
		break;
	case PE_WRITE_APPS:
		val = current_parameter_apps(PT_WRITE);
		break;
	default:
		break;
	}

	return val;
}

int do_set_energy(void)
{
	int ret = 0;

	init_data_energy();

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

void do_unset_energy(void)
{
	dbi_unregister_kretprobe(&switch_to_krp);
	dbi_unregister_kretprobe(&sys_write_krp);
	dbi_unregister_kretprobe(&sys_read_krp);

	uninit_data_energy();
}

static DEFINE_MUTEX(mutex_enable);
static int energy_enable = 0;

int set_energy(void)
{
	int ret = -EINVAL;

	mutex_lock(&mutex_enable);
	if (energy_enable) {
		printk("energy profiling is already run!\n");
		goto unlock;
	}

	ret = do_set_energy();
	if (ret == 0)
		energy_enable = 1;

unlock:
	mutex_unlock(&mutex_enable);

	return ret;
}
EXPORT_SYMBOL_GPL(set_energy);

int unset_energy(void)
{
	int ret = 0;

	mutex_lock(&mutex_enable);
	if (energy_enable == 0) {
		printk("energy profiling is not running!\n");
		ret = -EINVAL;
		goto unlock;
	}

	do_unset_energy();

	energy_enable = 0;
unlock:
	mutex_unlock(&mutex_enable);

	return ret;
}
EXPORT_SYMBOL_GPL(unset_energy);

int energy_init(void)
{
	int ret;
	unsigned long addr;

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
	if (ret)
		return ret;

	ret = lcd_init();
	if (ret)
		uninit_feature();

	return ret;
}

void energy_uninit(void)
{
	lcd_exit();
	uninit_feature();

	if (energy_enable)
		do_unset_energy();
}
