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

struct lcd_ops_get {
	int (*get_backlight)(void);
	int (*get_power)(void);
};

struct lcd_ops_set {
	void (*set_backlight)(int val);
	void (*set_power)(int val);
};

int lcd_mach_init(struct lcd_ops_set *ops_set, struct lcd_ops_get *ops_get);
void lcd_mach_exit(void);

int lcd_init(void);
void lcd_exit(void);

#endif /* _LCD_BASE_H */
