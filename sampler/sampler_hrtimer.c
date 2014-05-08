/*
 *  SWAP sampler
 *  modules/sampler/sampler_hrtimer.c
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP sampler porting
 *
 */



#include <linux/types.h>
#include "sampler_timers.h"


static u64 sampler_timer_quantum = 0;
static DEFINE_PER_CPU(struct hrtimer, swap_hrtimer);
static int swap_hrtimer_running;

restart_ret sampler_timers_restart(swap_timer *timer)
{
	restart_ret ret;

	hrtimer_forward_now(timer, ns_to_ktime(sampler_timer_quantum));
	ret = HRTIMER_RESTART;

	return ret;
}


void sampler_timers_set_run(void)
{
	swap_hrtimer_running = 1;
}


void sampler_timers_set_stop(void)
{
	swap_hrtimer_running = 0;
}


void sampler_timers_start(void *restart_func)
{
	struct hrtimer *hrtimer = &__get_cpu_var(swap_hrtimer);

	if (!swap_hrtimer_running)
		return;

	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer->function = restart_func;
	hrtimer_start(hrtimer, ns_to_ktime(sampler_timer_quantum),
		  HRTIMER_MODE_REL_PINNED);
}


void sampler_timers_stop(int cpu)
{
	struct hrtimer *hrtimer = &per_cpu(swap_hrtimer, cpu);

	if (!swap_hrtimer_running)
		return;

	hrtimer_cancel(hrtimer);
}


void sampler_timers_set_quantum(unsigned int timer_quantum)
{
	sampler_timer_quantum = timer_quantum * 1000 * 1000;
}
