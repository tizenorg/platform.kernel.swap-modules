#include <linux/module.h>
#include <linux/time.h>
#include <kprobe/dbi_kprobes.h>

static u64 get_ntime(void)
{
	struct timespec ts;

	getnstimeofday(&ts);

	return (u64)ts.tv_sec * 1000*1000*1000 + ts.tv_nsec;
}

/* ============================================================================
 * =                             __switch_to                                  =
 * ============================================================================
 */
static int entry_handler_switch(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int ret_handler_switch(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static struct kretprobe switch_to_krp = {
	.entry_handler = entry_handler_switch,
	.handler = ret_handler_switch,
};





/* ============================================================================
 * =                                sys_read                                  =
 * ============================================================================
 */
static int entry_handler_sys_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int ret_handler_sys_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static struct kretprobe sys_read_krp = {
	.entry_handler = entry_handler_sys_read,
	.handler = ret_handler_sys_read,
};





/* ============================================================================
 * =                               sys_write                                  =
 * ============================================================================
 */
static int entry_handler_sys_write(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int ret_handler_sys_write(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static struct kretprobe sys_write_krp = {
	.entry_handler = entry_handler_sys_write,
	.handler = ret_handler_sys_write,
};





int set_energy(void)
{
	int ret = 0;

	ret = dbi_register_kretprobe(&sys_read_krp);
	if (ret) {
		printk("dbi_register_kretprobe(sys_read) result=%d!\n", ret);
		return ret;
	}

	ret = dbi_register_kretprobe(&sys_write_krp);
	if (ret != 0) {
		printk("dbi_register_kretprobe(sys_write) result=%d!\n", ret);
		goto unregister_sys_read;
	}

	ret = dbi_register_kretprobe(&switch_to_krp);
	if (ret) {
		printk("dbi_register_kretprobe(__switch_to) result=%d!\n", ret);
		goto unregister_sys_write;
	}

	return ret;

unregister_sys_read:
	dbi_unregister_kretprobe(&sys_read_krp);

unregister_sys_write:
	dbi_unregister_kretprobe(&sys_write_krp);

	return ret;
}
EXPORT_SYMBOL_GPL(set_energy);

void unset_energy(void)
{
	dbi_unregister_kretprobe(&switch_to_krp);
	dbi_unregister_kretprobe(&sys_write_krp);
	dbi_unregister_kretprobe(&sys_read_krp);
}
EXPORT_SYMBOL_GPL(unset_energy);

static int __init swap_energy_init(void)
{
	unsigned long addr;
	addr = swap_ksyms("__switch_to");
	if (addr == 0) {
		printk("Cannot find address for __switch_to function!\n");
		return -EINVAL;
	}
	switch_to_krp.kp.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms("sys_read");
	if (addr == 0) {
		printk("Cannot find address for sys_read function!\n");
		return -EINVAL;
	}
	sys_read_krp.kp.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms("sys_write");
	if (addr == 0) {
		printk("Cannot find address for sys_write function!\n");
		return -EINVAL;
	}
	sys_write_krp.kp.addr = (kprobe_opcode_t *)addr;

	return 0;
}

static void __exit swap_energy_exit(void)
{
}

module_init(swap_energy_init);
module_exit(swap_energy_exit);

MODULE_LICENSE("GPL");
