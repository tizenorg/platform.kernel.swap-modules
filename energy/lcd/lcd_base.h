#ifndef _LCD_BASE_H
#define _LCD_BASE_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  energy/lcd/lcd_base.h
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


#include <linux/errno.h>
#include <energy/rational_debugfs.h>


enum lcd_action_type {
	LAT_BRIGHTNESS,
	LAT_POWER
};

enum lcd_parameter_type {
	LPD_MIN_BRIGHTNESS,
	LPD_MAX_BRIGHTNESS,
	LPD_BRIGHTNESS,

	LPD_POWER
};

struct lcd_ops;

typedef int (*call_lcd)(struct lcd_ops *ops);
typedef int (*notifier_lcd)(struct lcd_ops *ops, enum lcd_action_type action,
			    void *data);
typedef unsigned long (*get_parameter_lcd)(struct lcd_ops *ops,
					   enum lcd_parameter_type type);


struct lcd_ops {
	char *name;
	notifier_lcd notifier;
	get_parameter_lcd get;

	call_lcd check;
	call_lcd set;
	call_lcd unset;

	/* for debugfs */
	struct dentry *dentry;
	struct rational min_coef;
	struct rational max_coef;

	void *priv;
};

size_t get_lcd_size_array(struct lcd_ops *ops);
void get_lcd_array_time(struct lcd_ops *ops, u64 *array_time);

int read_val(const char *path);

int lcd_set_energy(void);
void lcd_unset_energy(void);

int lcd_init(void);
void lcd_exit(void);

#endif /* _LCD_BASE_H */
