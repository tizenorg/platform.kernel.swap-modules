#ifndef _US_DEF_HANDLER_H
#define _US_DEF_HANDLER_H

#include <asm/percpu.h>

struct us_ip;
struct pt_regs;
struct uretprobe_instance;

DECLARE_PER_CPU(struct us_ip *, gpCurIp);
DECLARE_PER_CPU(struct pt_regs *, gpUserRegs);

unsigned long ujprobe_event_pre_handler(struct us_ip *ip,
					struct pt_regs *regs);
void ujprobe_event_handler(unsigned long arg0, unsigned long arg1,
			   unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5);
int uretprobe_event_handler(struct uretprobe_instance *p,
			    struct pt_regs *regs, struct us_ip *ip);

#endif /* _US_DEF_HANDLER_H */
