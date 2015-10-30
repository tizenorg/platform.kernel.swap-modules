/*
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
 * Copyright (C) Samsung Electronics, 2015
 *
 * 2015         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <kprobe/swap_kprobes.h>
#include <ksyms/ksyms.h>
#include "swap_ktd.h"
#include "swap_td_raw.h"


#define KTD_PREFIX		"[SWAP_KTD] "
#define kTD_JOBCTL_PREPARE	(1 << 31)
#define KTD_BIT_MAX		(sizeof(unsigned long) * 8)


struct td {
	struct list_head list;
	struct task_struct *task;

	spinlock_t flags_lock;
	unsigned long init_flags;
};


static struct td_raw td_raw;
static LIST_HEAD(prepare_list);
static DEFINE_RWLOCK(prepare_lock);
static int preparing_cnt = 0;


static DEFINE_MUTEX(mutex_ktd_nr);
static struct ktask_data *ktd_array[KTD_BIT_MAX];


static bool ktd_init_is(struct ktask_data *ktd, struct td *td)
{
	return !!(td->init_flags & (1 << ktd->nr_bit));
}

static void ktd_init(struct ktask_data *ktd, struct td *td,
		     struct task_struct *task)
{
	unsigned long flags;

	spin_lock_irqsave(&td->flags_lock, flags);
	if (ktd_init_is(ktd, td))
		goto unlock;

	if (ktd->init)
		ktd->init(task, swap_td_raw(&ktd->td_raw, task));

	td->init_flags |= 1 << ktd->nr_bit;

unlock:
	spin_unlock_irqrestore(&td->flags_lock, flags);
}

static void ktd_exit_no_lock(struct ktask_data *ktd, struct td *td,
			     struct task_struct *task)
{
	if (ktd_init_is(ktd, td)) {
		if (ktd->exit)
			ktd->exit(task, swap_td_raw(&ktd->td_raw, task));

		td->init_flags &= ~(1 << ktd->nr_bit);
	}
}

static void ktd_exit_all(struct td *td, struct task_struct *task)
{
	unsigned long flags;
	unsigned long init_flags;
	int nr_bit = 0;

	spin_lock_irqsave(&td->flags_lock, flags);
	init_flags = td->init_flags;
	do {
		if (init_flags & 1)
			ktd_exit_no_lock(ktd_array[nr_bit], td, task);

		++nr_bit;
		init_flags >>= 1;
	} while (init_flags);
	td->init_flags = 0;
	spin_unlock_irqrestore(&td->flags_lock, flags);
}


static bool task_prepare_is(struct task_struct *task)
{
	return !!(task->jobctl & kTD_JOBCTL_PREPARE);
}

static void task_prepare_set(struct task_struct *task)
{
	if (!(task->jobctl & kTD_JOBCTL_PREPARE))
		task->jobctl |= kTD_JOBCTL_PREPARE;
	else
		WARN(1, KTD_PREFIX "already prepare");

	++preparing_cnt;
}

static void task_prepare_clear(struct task_struct *task)
{
	if (task->jobctl & kTD_JOBCTL_PREPARE)
		task->jobctl &= ~kTD_JOBCTL_PREPARE;
	else
		WARN(1, KTD_PREFIX "is not prepare");

	--preparing_cnt;
}

static struct task_struct *task_by_td(struct td *td)
{
	return td->task;
}

static struct td *td_by_task(struct task_struct *task)
{
	return (struct td *)swap_td_raw(&td_raw, task);
}


static void task_prepare(struct task_struct *task, struct td *td,
			 struct ktask_data *ktd)
{
	unsigned long flags;

	write_lock_irqsave(&prepare_lock, flags);

	/* skip multi-preparing task */
	if (task_prepare_is(task))
		goto unlock;

	task_prepare_set(task);

	INIT_LIST_HEAD(&td->list);
	td->task = task;
	spin_lock_init(&td->flags_lock);
	td->init_flags = 0;

	/* add to prepare_list */
	list_add(&td->list, &prepare_list);

unlock:
	write_unlock_irqrestore(&prepare_lock, flags);
}

static void ktd_exit_all(struct td *td, struct task_struct *task);

static void td_prepare_clear_no_lock(struct td *td, struct task_struct *task)
{
	if (task_prepare_is(task)) {
		task_prepare_clear(task);

		ktd_exit_all(td, task);

		/* delete from prepare_list */
		list_del(&td->list);
	}
}

static void td_prepare_clear(struct td *td, struct task_struct *task)
{
	unsigned long flags;

	write_lock_irqsave(&prepare_lock, flags);
	td_prepare_clear_no_lock(td, task);
	write_unlock_irqrestore(&prepare_lock, flags);
}

void *swap_ktd(struct ktask_data *ktd, struct task_struct *task)
{
	struct td *td = td_by_task(task);

	if (!likely(task_prepare_is(task)))
		task_prepare(task, td, ktd);

	if (!likely(ktd_init_is(ktd, td)))
		ktd_init(ktd, td, task);

	return swap_td_raw(&ktd->td_raw, task);
}
EXPORT_SYMBOL_GPL(swap_ktd);


static int ktd_nr_get_free_bit(void)
{
	int bit;

	for (bit = 0; bit < KTD_BIT_MAX; ++bit) {
		if (ktd_array[bit] == NULL)
			return bit;
	}

	return -ENOMEM;
}

int swap_ktd_reg(struct ktask_data *ktd)
{
	int ret;
	int free_bit;

	mutex_lock(&mutex_ktd_nr);
	free_bit = ktd_nr_get_free_bit();

	if (free_bit < 0) {
		ret = free_bit;
		goto unlock;
	}

	ret = swap_td_raw_reg(&ktd->td_raw, ktd->size);
	if (ret)
		goto unlock;

	ktd->nr_bit = free_bit;
	ktd_array[free_bit] = ktd;
unlock:
	mutex_unlock(&mutex_ktd_nr);
	return ret;
}
EXPORT_SYMBOL_GPL(swap_ktd_reg);

void swap_ktd_unreg(struct ktask_data *ktd)
{
	struct td *td;
	unsigned long flags;

	/* exit all task */
	read_lock_irqsave(&prepare_lock, flags);
	list_for_each_entry(td, &prepare_list, list) {
		spin_lock(&td->flags_lock);
		ktd_exit_no_lock(ktd, td, task_by_td(td));
		spin_unlock(&td->flags_lock);
	}
	read_unlock_irqrestore(&prepare_lock, flags);

	mutex_lock(&mutex_ktd_nr);

	ktd_array[ktd->nr_bit] = NULL;
	swap_td_raw_unreg(&ktd->td_raw);

	mutex_unlock(&mutex_ktd_nr);
}
EXPORT_SYMBOL_GPL(swap_ktd_unreg);


/*
 * void __put_task_struct(struct task_struct *tsk)
 */
static int put_ts_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *task;

	task = (struct task_struct *)swap_get_karg(regs, 0);

	if (task_prepare_is(task))
		td_prepare_clear(td_by_task(task), task);

	return 0;
}

static struct kprobe put_ts_kp = {
	.pre_handler = put_ts_handler
};


int swap_ktd_once(void)
{
	const char *sym;

	sym = "__put_task_struct";
	put_ts_kp.addr = (void *)swap_ksyms(sym);
	if (put_ts_kp.addr == NULL)
		goto not_found;

	return 0;

not_found:
	pr_err(KTD_PREFIX "ERROR: symbol %s(...) not found\n", sym);
	return -ESRCH;
}

int swap_ktd_init(void)
{
	int ret;

	WARN(preparing_cnt, KTD_PREFIX "preparing_cnt=%d", preparing_cnt);

	preparing_cnt = 0;

	ret = swap_td_raw_reg(&td_raw, sizeof(struct td));
	if (ret)
		goto fail;

	ret = swap_register_kprobe(&put_ts_kp);
	if (ret)
		goto td_raw_unreg;

	return 0;

td_raw_unreg:
	swap_td_raw_unreg(&td_raw);
fail:
	pr_err(KTD_PREFIX "registration failed, ret=%d", ret);
	return ret;
}

void swap_ktd_uninit(void)
{
	struct td *td, *n;
	unsigned long flags;

	/* remove td injection from tasks */
	write_lock_irqsave(&prepare_lock, flags);
	list_for_each_entry_safe(td, n, &prepare_list, list)
		td_prepare_clear_no_lock(td, task_by_td(td));
	write_unlock_irqrestore(&prepare_lock, flags);

	swap_unregister_kprobe(&put_ts_kp);
	swap_td_raw_unreg(&td_raw);

	WARN(preparing_cnt, KTD_PREFIX "preparing_cnt=%d", preparing_cnt);
}
