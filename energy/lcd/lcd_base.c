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
#include <energy/tm_stat.h>
#include "lcd_base.h"
#include "lcd_debugfs.h"


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
	brt_no_init = -1,
	brt_cnt = 10
};

struct lcd_priv_data {
	int min_brt;
	int max_brt;

	size_t tms_brt_cnt;
	struct tm_stat *tms_brt;
	spinlock_t lock_tms;
	int brt_old;

	u64 min_denom;
	u64 min_num;
	u64 max_denom;
	u64 max_num;
};

static void *create_lcd_priv(struct lcd_ops *ops, size_t tms_brt_cnt)
{
	int i;
	struct lcd_priv_data *lcd;

	if (tms_brt_cnt <= 0) {
		printk("error variable tms_brt_cnt=%d\n", tms_brt_cnt);
		return NULL;
	}

	lcd = kmalloc(sizeof(*lcd) + sizeof(*lcd->tms_brt) * tms_brt_cnt,
		      GFP_KERNEL);
	if (lcd == NULL) {
		printk("error: %s - out of memory\n", __func__);
		return NULL;
	}

	lcd->tms_brt = (void *)lcd + sizeof(*lcd);
	lcd->tms_brt_cnt = tms_brt_cnt;

	lcd->min_brt = ops->get(ops, LPD_MIN_BRIGHTNESS);
	lcd->max_brt = ops->get(ops, LPD_MAX_BRIGHTNESS);

	for (i = 0; i < tms_brt_cnt; ++i)
		tm_stat_init(&lcd->tms_brt[i]);

	spin_lock_init(&lcd->lock_tms);

	lcd->brt_old = brt_no_init;

	lcd->min_denom = 1;
	lcd->min_num = 1;
	lcd->max_denom = 1;
	lcd->max_num = 1;

	return (void *)lcd;
}

static void destroy_lcd_priv(void *data)
{
	kfree(data);
}

static struct lcd_priv_data *get_lcd_priv(struct lcd_ops *ops)
{
	return (struct lcd_priv_data *)ops->priv;
}

static void set_brightness(struct lcd_ops *ops, int brt)
{
	struct lcd_priv_data *lcd = get_lcd_priv(ops);
	int n;

	if (brt > lcd->max_brt || brt < lcd->min_brt) {
		printk("LCD energy error: set brightness=%d, "
		       "when brightness[%d..%d]\n",
		       brt, lcd->min_brt, lcd->max_brt);
		brt = brt > lcd->max_brt ? lcd->max_brt : lcd->min_brt;
	}

	n = lcd->tms_brt_cnt * (brt - lcd->min_brt) /
	    (lcd->max_brt - lcd->min_brt + 1);

	spin_lock(&lcd->lock_tms);
	if (lcd->brt_old != n) {
		u64 time = get_ntime();
		if (lcd->brt_old != brt_no_init)
			tm_stat_update(&lcd->tms_brt[lcd->brt_old], time);

		tm_stat_set_timestamp(&lcd->tms_brt[n], time);
		lcd->brt_old = n;
	}
	spin_unlock(&lcd->lock_tms);
}

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

static LIST_HEAD(lcd_list);
static DEFINE_MUTEX(lcd_lock);

static void add_lcd(struct lcd_ops *ops)
{
	ops->priv = create_lcd_priv(ops, brt_cnt);

	/* TODO: create init_func() for 'struct rational' */
	ops->min_coef.num = 1;
	ops->min_coef.denom = 1;
	ops->max_coef.num = 1;
	ops->max_coef.denom = 1;

	ops->notifier = func_notifier_lcd;
	set_brightness(ops, ops->get(ops, LPD_BRIGHTNESS));

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

size_t get_lcd_size_array(struct lcd_ops *ops)
{
	struct lcd_priv_data *lcd = get_lcd_priv(ops);

	return lcd->tms_brt_cnt;
}

void get_lcd_array_time(struct lcd_ops *ops, u64 *array_time)
{
	struct lcd_priv_data *lcd = get_lcd_priv(ops);
	int i;

	spin_lock(&lcd->lock_tms);
	for (i = 0; i < lcd->tms_brt_cnt; ++i) {
		array_time[i] = tm_stat_running(&lcd->tms_brt[i]);
		if (i == lcd->brt_old)
			array_time[i] += get_ntime() -
					 tm_stat_timestamp(&lcd->tms_brt[i]);
	}
	spin_unlock(&lcd->lock_tms);
}

int register_lcd(struct lcd_ops *ops)
{
	int ret = 0;

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
	ret = register_lcd_debugfs(ops);
	if (ret)
		del_lcd(ops);

unlock:
	mutex_unlock(&lcd_lock);
	return ret;
}

void unregister_lcd(struct lcd_ops *ops)
{
	mutex_lock(&lcd_lock);
	if (lcd_is_register(ops) == 0)
		goto unlock;

	unregister_lcd_debugfs(ops);
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
