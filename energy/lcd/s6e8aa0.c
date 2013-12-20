#include <kprobe/dbi_kprobes.h>
#include "lcd_base.h"


static const char path_backlight[]	= "/sys/class/backlight/s6e8aa0-bl/brightness";
static const char path_backlight_min[]	= "/sys/class/backlight/s6e8aa0-bl/min_brightness";
static const char path_backlight_max[]	= "/sys/class/backlight/s6e8aa0-bl/max_brightness";

static const char *all_path[] = {
	path_backlight,
	path_backlight_min,
	path_backlight_max
};

enum {
	all_path_cnt = sizeof(all_path) / sizeof(char *)
};



static int s6e8aa0_check(struct lcd_ops *ops)
{
	int i;

	for (i = 0; i < all_path_cnt; ++i) {
		int ret = read_val(all_path[i]);

		if (IS_ERR_VALUE(ret))
			return 0;
	}

	return 1;
}

static unsigned long s6e8aa0_get_parameter(struct lcd_ops *ops,
					   enum lcd_parameter_type type)
{
	switch (type) {
	case LPD_MIN_BRIGHTNESS:
		return read_val(path_backlight_min);
	case LPD_MAX_BRIGHTNESS:
		return read_val(path_backlight_max);
	case LPD_BRIGHTNESS:
		return read_val(path_backlight);
	default:
		return -EINVAL;
	}
}





#if 0 /* is not supported */
/* ============================================================================
 * ===                               POWER                                  ===
 * ============================================================================
 */
static int get_power(void)
{
	const char *power_path = "/sys/class/lcd/s6e8aa0/lcd_power";

	return read_val(power_path);
}

static int entry_handler_set_power(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	int *power = (int *)ri->data;

	*power = (int)regs->ARM_r1;

	return 0;
}

static int ret_handler_set_power(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	int ret = regs_return_value(regs);
	int *power = (int *)ri->data;

	if (!ret && ops_s && ops_s->set_power)
		ops_s->set_power(*power);

	return 0;
}

static struct kretprobe set_power_krp = {
	.kp.symbol_name = "s6e8aa0_set_power",
	.entry_handler = entry_handler_set_power,
	.handler = ret_handler_set_power,
	.data_size = sizeof(int)
};
#endif



static int entry_handler_set_backlight(struct kretprobe_instance *ri,
				       struct pt_regs *regs);
static int ret_handler_set_backlight(struct kretprobe_instance *ri,
				     struct pt_regs *regs);

static struct kretprobe set_backlight_krp = {
	.kp.symbol_name = "s6e8aa0_gamma_ctrl",
	.entry_handler = entry_handler_set_backlight,
	.handler = ret_handler_set_backlight,
	.data_size = sizeof(int)
};

int s6e8aa0_set(struct lcd_ops *ops)
{
	return dbi_register_kretprobe(&set_backlight_krp);
}

int s6e8aa0_unset(struct lcd_ops *ops)
{
	dbi_unregister_kretprobe(&set_backlight_krp);
	return 0;
}

static struct lcd_ops s6e8aa0_ops = {
	.name = "s6e8aa0",
	.check = s6e8aa0_check,
	.set = s6e8aa0_set,
	.unset = s6e8aa0_unset,
	.get = s6e8aa0_get_parameter
};

struct lcd_ops *LCD_MAKE_FNAME(s6e8aa0)(void)
{
	return &s6e8aa0_ops;
}





/* ============================================================================
 * ===                              BACKLIGHT                               ===
 * ============================================================================
 */
static int entry_handler_set_backlight(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	int *brightness = (int *)ri->data;
	*brightness = (int)swap_get_karg(regs, 1);

	return 0;
}

static int ret_handler_set_backlight(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	int ret = regs_return_value(regs);
	int *brightness = (int *)ri->data;

	if (!ret && s6e8aa0_ops.notifier)
		s6e8aa0_ops.notifier(&s6e8aa0_ops, LAT_BRIGHTNESS,
				     (void *)*brightness);

	return 0;
}
