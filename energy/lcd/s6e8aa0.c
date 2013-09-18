#include <kprobe/dbi_kprobes.h>
#include "lcd_base.h"

static struct lcd_ops_set *ops_s = NULL;


static int read_val(const char *path)
{
	int ret;
	struct file *f;
	unsigned long val;
	char buf[32];

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		printk("cannot open file \'%s\'", path);
		return PTR_ERR(f);
	}

	ret = kernel_read(f, 0, buf, sizeof(buf));
	filp_close(f, NULL);
	if (ret < 0)
		return ret;

	ret = strict_strtoul(buf, 0, &val);
	if (ret)
		return ret;

	return (int)val;
}





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





/* ============================================================================
 * ===                              BACKLIGHT                               ===
 * ============================================================================
 */
static int get_backlight(void)
{
	const char *backlight_path = "/sys/class/backlight/s6e8aa0-bl/brightness";

	return read_val(backlight_path);
}

static int entry_handler_set_backlight(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	int *brightness = (int *)ri->data;
	*brightness = (int)regs->ARM_r1;

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
	.kp.symbol_name = "s6e8aa0_gamma_ctrl",
	.entry_handler = entry_handler_set_backlight,
	.handler = ret_handler_set_backlight,
	.data_size = sizeof(struct backlight_device *)
};





int lcd_mach_init(struct lcd_ops_set *ops_set, struct lcd_ops_get *ops_get)
{
	int ret;

	ret = dbi_register_kretprobe(&set_power_krp);
	if (ret) {
		goto unregister_power_krp;
	}

	ret = dbi_register_kretprobe(&set_backlight_krp);
	if (ret) {
		return ret;
	}

	ops_s = ops_set;
	ops_get->get_power = get_power;
	ops_get->get_backlight = get_backlight;

	return 0;

unregister_power_krp:
	dbi_unregister_kretprobe(&set_power_krp);

	return ret;
}

void lcd_mach_exit(void)
{
	dbi_unregister_kretprobe(&set_backlight_krp);
	dbi_unregister_kretprobe(&set_power_krp);
	ops_s = NULL;
}
