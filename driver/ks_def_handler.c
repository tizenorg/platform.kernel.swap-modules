#include <linux/module.h>
#include <asm/percpu.h>
#include "probes_manager.h"

DEFINE_PER_CPU(kernel_probe_t *, gpKernProbe) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpKernProbe);

unsigned long def_jprobe_event_pre_handler(kernel_probe_t *p,
					   struct pt_regs *regs)
{
	__get_cpu_var(gpKernProbe) = p;

	return 0;
}
EXPORT_SYMBOL_GPL(def_jprobe_event_pre_handler);

void def_jprobe_event_handler(unsigned long arg0, unsigned long arg1,
			      unsigned long arg2, unsigned long arg3,
			      unsigned long arg4, unsigned long arg5)
{
	kernel_probe_t *p = __get_cpu_var(gpKernProbe);

	pack_event_info(KS_PROBE_ID, RECORD_ENTRY, "pxxxxxx", p->addr,
			arg0, arg1, arg2, arg3, arg4, arg5);
	dbi_jprobe_return();
}
EXPORT_SYMBOL_GPL(def_jprobe_event_handler);

int def_retprobe_event_handler(struct kretprobe_instance *ri,
			       struct pt_regs *regs, kernel_probe_t *p)
{
	int ret_val;

	ret_val = regs_return_value(regs);
	pack_event_info(KS_PROBE_ID, RECORD_RET, "pd", p->addr, ret_val);

	return 0;
}
EXPORT_SYMBOL_GPL(def_retprobe_event_handler);
