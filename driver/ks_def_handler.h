#ifndef _KS_DEF_HANDLER_H
#define _KS_DEF_HANDLER_H

#include <asm/percpu.h>

struct pt_regs;
struct kern_probe;
struct kretprobe_instance;

DECLARE_PER_CPU(struct kern_probe *, gpKernProbe);

unsigned long def_jprobe_event_pre_handler(struct kern_probe *p,
					   struct pt_regs *regs);
void def_jprobe_event_handler(unsigned long arg0, unsigned long arg1,
			      unsigned long arg2, unsigned long arg3,
			      unsigned long arg4, unsigned long arg5);
int def_retprobe_event_handler(struct kretprobe_instance *ri,
			       struct pt_regs *regs, struct kern_probe *p);

#endif /* _KS_DEF_HANDLER_H */
