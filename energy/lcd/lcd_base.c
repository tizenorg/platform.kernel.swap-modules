/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  energy/lcd/lcd_base.c
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
 * 2013         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/module.h>
#include "lcd_base.h"


void set_backlight(int val)
{
	/* TODO: implement */
}

void set_power(int val)
{
	/* TODO: implement */
}

static struct lcd_ops_set ops_set = {
	.set_backlight = set_backlight,
	.set_power = set_power
};

static struct lcd_ops_get ops_get = { NULL, NULL };

int lcd_init(void)
{
	int ret;

	ret = lcd_mach_init(&ops_set, &ops_get);
	if (ret)
		return ret;

	return ret;
}

void lcd_exit(void)
{
	lcd_mach_exit();
}
