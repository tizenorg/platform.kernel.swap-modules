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

static void clean_brightness(struct lcd_ops *ops)
{
	struct lcd_priv_data *lcd = get_lcd_priv(ops);
	int i;

	spin_lock(&lcd->lock_tms);
	for (i = 0; i < lcd->tms_brt_cnt; ++i)
		tm_stat_init(&lcd->tms_brt[i]);

	lcd->brt_old = brt_no_init;
	spin_unlock(&lcd->lock_tms);
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

static int register_lcd(struct lcd_ops *ops)
{
	int ret = 0;

	ops->priv = create_lcd_priv(ops, brt_cnt);

	/* TODO: create init_func() for 'struct rational' */
	ops->min_coef.num = 1;
	ops->min_coef.denom = 1;
	ops->max_coef.num = 1;
	ops->max_coef.denom = 1;

	ops->notifier = func_notifier_lcd;

	ret = register_lcd_debugfs(ops);
	if (ret)
		destroy_lcd_priv(ops->priv);

	return ret;
}

static void unregister_lcd(struct lcd_ops *ops)
{
	unregister_lcd_debugfs(ops);
	destroy_lcd_priv(ops->priv);
}




/* ============================================================================
 * ===                          LCD_INIT/LCD_EXIT                           ===
 * ============================================================================
 */
typedef struct lcd_ops *(*get_ops_t)(void);

DEFINITION_LCD_FUNC;

get_ops_t lcd_ops[] = DEFINITION_LCD_ARRAY;
enum { lcd_ops_cnt = sizeof(lcd_ops) / sizeof(get_ops_t) };

enum ST_LCD_OPS {
	SLO_REGISTER	= 1 << 0,
	SLO_SET		= 1 << 1
};

static DEFINE_MUTEX(lcd_lock);
static enum ST_LCD_OPS stat_lcd_ops[lcd_ops_cnt];

void lcd_exit(void)
{
	int i;
	struct lcd_ops *ops;

	mutex_lock(&lcd_lock);
	for (i = 0; i < lcd_ops_cnt; ++i) {
		ops = lcd_ops[i]();

		if (stat_lcd_ops[i] & SLO_SET) {
			ops->unset(ops);
			stat_lcd_ops[i] &= ~SLO_SET;
		}

		if (stat_lcd_ops[i] & SLO_REGISTER) {
			unregister_lcd(ops);
			stat_lcd_ops[i] &= ~SLO_REGISTER;
		}
	}
	mutex_unlock(&lcd_lock);
}

int lcd_init(void)
{
	int i, ret, count = 0;
	struct lcd_ops *ops;

	mutex_lock(&lcd_lock);
	for (i = 0; i < lcd_ops_cnt; ++i) {
		ops = lcd_ops[i]();
		if (ops == NULL) {
			printk("error %s [ops == NULL]\n", ops->name);
			continue;
		}

		if (0 == ops->check(ops)) {
			printk("error checking %s\n", ops->name);
			continue;
		}

		ret = register_lcd(ops);
		if (ret) {
			printk("error register_lcd %s\n", ops->name);
			continue;
		}

		stat_lcd_ops[i] |= SLO_REGISTER;
		++count;
	}
	mutex_unlock(&lcd_lock);

	return count ? 0 : -EPERM;
}





/* ============================================================================
 * ===                     LCD_SET_ENERGY/LCD_UNSET_ENERGY                  ===
 * ============================================================================
 */
int lcd_set_energy(void)
{
	int i, ret, count = 0;
	struct lcd_ops *ops;

	mutex_lock(&lcd_lock);
	for (i = 0; i < lcd_ops_cnt; ++i) {
		ops = lcd_ops[i]();
		if (stat_lcd_ops[i] & SLO_REGISTER) {
			ret = ops->set(ops);
			if (ret) {
				printk("error %s set LCD energy", ops->name);
				continue;
			}

			set_brightness(ops, ops->get(ops, LPD_BRIGHTNESS));

			stat_lcd_ops[i] |= SLO_SET;
			++count;
		}
	}
	mutex_unlock(&lcd_lock);

	return count ? 0 : -EPERM;
}

void lcd_unset_energy(void)
{
	int i, ret;
	struct lcd_ops *ops;

	mutex_lock(&lcd_lock);
	for (i = 0; i < lcd_ops_cnt; ++i) {
		ops = lcd_ops[i]();
		if (stat_lcd_ops[i] & SLO_SET) {
			ret = ops->unset(ops);
			if (ret)
				printk("error %s unset LCD energy", ops->name);

			clean_brightness(ops);
			stat_lcd_ops[i] &= ~SLO_SET;
		}
	}
	mutex_unlock(&lcd_lock);
}
