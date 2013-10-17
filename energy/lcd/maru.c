/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  energy/lcd/maru.c
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


#include <kprobe/dbi_kprobes.h>
#include <linux/backlight.h>
#include "lcd_base.h"

static struct lcd_ops_set *ops_s = NULL;





/* ============================================================================
 * ===                               POWER                                  ===
 * ============================================================================
 */
static int get_power(void)
{
	/* in drivers/maru/maru_lcd.c value 'lcd_power' constant and zero */
	return 0;
}





/* ============================================================================
 * ===                              BACKLIGHT                               ===
 * ============================================================================
 */
static int get_backlight(void)
{
	const char *backlight_path = "/sys/class/backlight/emulator/brightness";

	return read_val(backlight_path);
}

static int entry_handler_set_backlight(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	int *brightness = (int *)ri->data;
	struct backlight_device *bd = (struct backlight_device *)regs->ax;
	*brightness = bd->props.brightness;

	return 0;
}

static int ret_handler_set_backlight(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	int ret = regs_return_value(regs);
	int *brightness = (int *)ri->data;

	if (!ret && ops_s && ops_s->set_backlight)
		ops_s->set_backlight(*brightness);

	return 0;
}

static struct kretprobe set_backlight_krp = {
	.kp.symbol_name = "marubl_send_intensity",
	.entry_handler = entry_handler_set_backlight,
	.handler = ret_handler_set_backlight,
	.data_size = sizeof(int)
};





/* ============================================================================
 * ===                              INIT/EXIT                               ===
 * ============================================================================
 */
int lcd_mach_init(struct lcd_ops_set *ops_set, struct lcd_ops_get *ops_get)
{
	int ret = 0;

	ret = dbi_register_kretprobe(&set_backlight_krp);
	if (ret)
		return ret;

	ops_s = ops_set;
	ops_get->get_power = get_power;
	ops_get->get_backlight = get_backlight;

	return ret;
}

void lcd_mach_exit(void)
{
	dbi_unregister_kretprobe(&set_backlight_krp);
	ops_s = NULL;
}
