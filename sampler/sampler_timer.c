/*
 *  SWAP sampler
 *  modules/sampler/sampler_timer.c
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



#include "sampler_timers.h"



static unsigned long sampler_timer_quantum = 0;
static DEFINE_PER_CPU(struct timer_list, dbi_timer);
static int dbi_timer_running;


restart_ret sampler_timers_restart(swap_timer *timer)
{
	restart_ret ret;

	mod_timer_pinned((struct timer_list *)timer,
		     jiffies + sampler_timer_quantum);
	ret = 0;

	return ret;
}


void sampler_timers_set_run(void)
{
	dbi_timer_running = 1;
}


void sampler_timers_set_stop(void)
{
	dbi_timer_running = 0;
}


void sampler_timers_start(void *restart_func)
{
	struct timer_list *timer = &__get_cpu_var(dbi_timer);

	if (!dbi_timer_running)
		return;

	init_timer(timer);
	timer->data = (unsigned long)timer;
	timer->function = restart_func;

	mod_timer_pinned(timer, jiffies + sampler_timer_quantum);
}


void sampler_timers_stop(int cpu)
{
	struct timer_list *timer = &per_cpu(dbi_timer, cpu);

	if (!dbi_timer_running)
		return;
	del_timer_sync(timer);
}


void sampler_timers_set_quantum(unsigned int timer_quantum)
{
	sampler_timer_quantum = timer_quantum;
}
