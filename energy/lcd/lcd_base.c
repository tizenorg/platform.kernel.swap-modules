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
#include <linux/slab.h>
#include <linux/fs.h>
#include "lcd_base.h"


int read_val(const char *path)
{
	int ret;
	struct file *f;
	unsigned long val;
	enum { buf_len = 32 };
	char buf[buf_len];

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		printk("cannot open file \'%s\'", path);
		return PTR_ERR(f);
	}

	ret = kernel_read(f, 0, buf, sizeof(buf));
	filp_close(f, NULL);
	if (ret < 0)
		return ret;

	buf[ret >= buf_len ? buf_len - 1 : ret] = '\0';

	ret = strict_strtoul(buf, 0, &val);
	if (ret)
		return ret;

	return (int)val;
}

enum {
	brightness_cnt = 10
};

void set_brightness(struct lcd_ops *ops, int val)
{
	/* TODO: implement */
	printk("####### set_backlight: name=%s val=%d\n", ops->name, val);
}

struct lcd_priv_data {
	int min_brightness;
	int max_brightness;

	int brightness[brightness_cnt];

	/* W = slope * brightness + intercept */
	u64 slope_denominator;
	u64 slope_numenator;
	u64 intercept_denominator;
	u64 intercept_numenator;
};

static int func_notifier_lcd(struct lcd_ops *ops, enum lcd_action_type action,
			     void *data)
{
	switch (action) {
	case LAT_BRIGHTNESS:
		set_brightness(ops, (int)data);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void *create_lcd_priv(struct lcd_ops *ops)
{
	int i;
	struct lcd_priv_data *lpd = kmalloc(sizeof(*lpd), GFP_KERNEL);

	lpd->min_brightness = ops->get(ops, LPD_MIN_BRIGHTNESS);
	lpd->max_brightness = ops->get(ops, LPD_MAX_BRIGHTNESS);

	for (i = 0; i < brightness_cnt; ++i)
		lpd->brightness[i] = 0;

	lpd->slope_denominator = 1;
	lpd->slope_numenator = 1;
	lpd->intercept_denominator = 1;
	lpd->intercept_numenator = 1;

	return (void *)lpd;
}

static void destroy_lcd_priv(void *data)
{
	kfree(data);
}

static LIST_HEAD(lcd_list);
static DEFINE_MUTEX(lcd_lock);

static void add_lcd(struct lcd_ops *ops)
{
	ops->priv = create_lcd_priv(ops);
	ops->notifler = func_notifier_lcd;

	INIT_LIST_HEAD(&ops->list);
	list_add(&ops->list, &lcd_list);
}

static void del_lcd(struct lcd_ops *ops)
{
	list_del(&ops->list);

	destroy_lcd_priv(ops->priv);
}

static struct lcd_ops *find_lcd(const char *name)
{
	struct lcd_ops *ops;

	list_for_each_entry(ops, &lcd_list, list)
		if (strcmp(ops->name, name) == 0)
			return ops;

	return NULL;
}

static int lcd_is_register(struct lcd_ops *ops)
{
	struct lcd_ops *o;

	list_for_each_entry(o, &lcd_list, list)
		if (o == ops)
			return 1;

	return 0;
}

int register_lcd(struct lcd_ops *ops)
{
	int ret;

	if (ops->check() == 0) {
		printk("error checking %s\n", ops->name);
		return -EINVAL;
	}

	mutex_lock(&lcd_lock);
	if (find_lcd(ops->name)) {
		ret = -EINVAL;
		goto unlock;
	}

	add_lcd(ops);

unlock:
	mutex_unlock(&lcd_lock);
	return ret;
}

void unregister_lcd(struct lcd_ops *ops)
{
	mutex_lock(&lcd_lock);
	if (lcd_is_register(ops) == 0)
		goto unlock;

	del_lcd(ops);

unlock:
	mutex_unlock(&lcd_lock);
}


DEFINITION_REG_FUNC;
DEFINITION_UNREG_FUNC;

void lcd_exit(void)
{
	UNREGISTER_ALL_FUNC();
}

int lcd_init(void)
{
	REGISTER_ALL_FUNC();

	return 0;
}
