/*
 *  SWAP sampler
 *  modules/sampler/swap_sampler_module.c
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
 * 2012  Andreev S.V.: SWAP Sampler implementation
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP sampler porting
 *
 */

#include <linux/timer.h>
#include <asm/ptrace.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <linux/jiffies.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/hrtimer.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/module.h>

#include <writer/swap_writer_module.h>

#include "swap_sampler_module.h"
#include "swap_sampler_errors.h"
#include "kernel_operations.h"


unsigned int dbi_timer_quantum = 0;

#ifdef CONFIG_HIGH_RES_TIMERS
static DEFINE_PER_CPU(struct hrtimer, dbi_hrtimer);
static int dbi_hrtimer_running;
#else
static DEFINE_PER_CPU(struct timer_list, dbi_timer);
static int dbi_timer_running;
#endif

static BLOCKING_NOTIFIER_HEAD(swap_sampler_notifier_list);


#ifdef CONFIG_HIGH_RES_TIMERS
static enum hrtimer_restart dbi_hrtimer_notify(struct hrtimer *hrtimer)
{
	if (current)
		sample_msg(task_pt_regs(current));

	hrtimer_forward_now(hrtimer, ns_to_ktime(dbi_timer_quantum));

	return HRTIMER_RESTART;
}

static void __dbi_hrtimer_start(void *unused)
{
	struct hrtimer *hrtimer = &__get_cpu_var(dbi_hrtimer);

	if (!dbi_hrtimer_running)
		return;

	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer->function = dbi_hrtimer_notify;
	hrtimer_start(hrtimer, ns_to_ktime(dbi_timer_quantum),
		      HRTIMER_MODE_REL_PINNED);
}

static int dbi_hrtimer_start(void)
{
	get_online_cpus();
	dbi_hrtimer_running = 1;
	on_each_cpu(__dbi_hrtimer_start, NULL, 1);
	put_online_cpus();

	return E_SS_SUCCESS;
}

static void __dbi_hrtimer_stop(int cpu)
{
	struct hrtimer *hrtimer = &per_cpu(dbi_hrtimer, cpu);

	if (!dbi_hrtimer_running)
		return;

	hrtimer_cancel(hrtimer);
}

static void dbi_hrtimer_stop(void)
{
	int cpu;

	get_online_cpus();

	for_each_online_cpu(cpu)
		__dbi_hrtimer_stop(cpu);

	dbi_hrtimer_running = 0;
	put_online_cpus();
}

#else

void dbi_write_sample_data(unsigned long data)
{
	struct timer_list *timer = (struct timer_list *)data;

	if (current)
		sample_msg(task_pt_regs(current));

	/* TODO: test pinning */
	mod_timer_pinned(timer, jiffies + dbi_timer_quantum);
}

static void __dbi_timer_start(void *unused)
{
	struct timer_list *timer = &__get_cpu_var(dbi_timer);

	if (!dbi_timer_running)
		return;

	init_timer(timer);
	timer->data = timer;
	timer->function = dbi_write_sample_data;

	/* TODO: test pinning */
	mod_timer_pinned(timer, jiffies + dbi_timer_quantum);
}

static int dbi_timer_start(void)
{
	get_online_cpus();
	dbi_timer_running = 1;
	on_each_cpu(__dbi_timer_start, NULL, 1);
	put_online_cpus();

	return E_SS_SUCCESS;
}

static void __dbi_timer_stop(int cpu)
{
	struct timer_list *timer = &per_cpu(dbi_timer, cpu);

	if (!dbi_timer_running)
		return;
	del_timer_sync(timer);
}

static void dbi_timer_stop(void)
{
	int cpu;

	get_online_cpus();

	for_each_online_cpu(cpu)
		__dbi_timer_stop(cpu);

	dbi_timer_running = 0;
	put_online_cpus();
}

#endif

static int __cpuinit dbi_cpu_notify(struct notifier_block *self,
				    unsigned long action, void *hcpu)
{
	long cpu = (long) hcpu;

	switch (action) {
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
#ifdef CONFIG_HIGH_RES_TIMERS
		smp_call_function_single(cpu, __dbi_hrtimer_start, NULL, 1);
#else
		smp_call_function_single(cpu, __dbi_timer_start, NULL, 1);
#endif
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
#ifdef CONFIG_HIGH_RES_TIMERS
		__dbi_hrtimer_stop(cpu);
#else
		__dbi_timer_stop(cpu);
#endif
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block __refdata dbi_cpu_notifier = {
	.notifier_call = dbi_cpu_notify,
};

static int do_swap_sampler_start(unsigned int timer_quantum)
{
	if (timer_quantum <= 0)
		return -EINVAL;

	dbi_timer_quantum = timer_quantum * 1000 * 1000;

#ifdef CONFIG_HIGH_RES_TIMERS
	dbi_hrtimer_start();
#else
	dbi_timer_start();
#endif

	return 0;
}

static void do_swap_sampler_stop(void)
{
#ifdef CONFIG_HIGH_RES_TIMERS
	dbi_hrtimer_stop();
#else
	dbi_timer_stop();
#endif
}

static DEFINE_MUTEX(mutex_run);
static int sampler_run = 0;

int swap_sampler_start(unsigned int timer_quantum)
{
	int ret = -EINVAL;

	mutex_lock(&mutex_run);
	if (sampler_run) {
		printk("sampler profiling is already run!\n");
		goto unlock;
	}

	ret = do_swap_sampler_start(timer_quantum);
	if (ret == 0)
		sampler_run = 1;

unlock:
	mutex_unlock(&mutex_run);

	return ret;
}
EXPORT_SYMBOL_GPL(swap_sampler_start);

int swap_sampler_stop(void)
{
	int ret = 0;

	mutex_lock(&mutex_run);
	if (sampler_run == 0) {
		printk("energy profiling is not running!\n");
		ret = -EINVAL;
		goto unlock;
	}

	do_swap_sampler_stop();

	sampler_run = 0;
unlock:
	mutex_unlock(&mutex_run);

	return ret;
}
EXPORT_SYMBOL_GPL(swap_sampler_stop);

static int __init sampler_init(void)
{
	int retval;

	retval = register_hotcpu_notifier(&dbi_cpu_notifier);
	if (retval) {
		print_err("Error of register_hotcpu_notifier()\n");
		return retval;
	}

	print_msg("Sample ininitialization success\n");

	return E_SS_SUCCESS;
}

static void __exit sampler_exit(void)
{
	if (sampler_run)
		do_swap_sampler_stop();

	unregister_hotcpu_notifier(&dbi_cpu_notifier);

	print_msg("Sampler uninitialized\n");
}

module_init(sampler_init);
module_exit(sampler_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP sampling module");
MODULE_AUTHOR("Andreev S.V., Aksenov A.S.");
