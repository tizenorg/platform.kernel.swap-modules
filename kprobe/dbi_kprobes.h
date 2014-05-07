#ifndef _DBI_KPROBES_H
#define _DBI_KPROBES_H

/*
 *  Kernel Probes (KProbes)
 *  include/linux/kprobes.h
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
 * Copyright (C) IBM Corporation, 2002, 2004
 */

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/dbi_kprobes.h
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
 * Copyright (C) Samsung Electronics, 2006-2010
 *
 * 2006-2007    Ekaterina Gorelkina <e.gorelkina@samsung.com>: initial implementation for ARM and MIPS
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts
 *
 */


#include <linux/version.h>	// LINUX_VERSION_CODE, KERNEL_VERSION()
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/pagemap.h>

#include <kprobe/arch/asm/dbi_kprobes.h>


#ifdef CONFIG_ARM

#define regs_return_value(regs)     ((regs)->ARM_r0)

#endif


/* kprobe_status settings */
#define KPROBE_HIT_ACTIVE	0x00000001
#define KPROBE_HIT_SS		0x00000002
#define KPROBE_REENTER		0x00000004
#define KPROBE_HIT_SSDONE	0x00000008

#define HIWORD(x)               (((x) & 0xFFFF0000) >> 16)
#define LOWORD(x)               ((x) & 0x0000FFFF)

#define INVALID_VALUE           0xFFFFFFFF
#define INVALID_POINTER         (void*)INVALID_VALUE

#define JPROBE_ENTRY(pentry)    (kprobe_opcode_t *)pentry

#define RETPROBE_STACK_DEPTH 64

struct kprobe;
struct pt_regs;
struct kretprobe;
struct kretprobe_instance;
typedef int (*kprobe_pre_handler_t) (struct kprobe *, struct pt_regs *);
typedef int (*kprobe_break_handler_t) (struct kprobe *, struct pt_regs *);
typedef void (*kprobe_post_handler_t) (struct kprobe *, struct pt_regs *, unsigned long flags);
typedef int (*kprobe_fault_handler_t) (struct kprobe *, struct pt_regs *, int trapnr);
typedef int (*kretprobe_handler_t) (struct kretprobe_instance *, struct pt_regs *);

struct kprobe
{
	struct hlist_node				hlist;
	/*list of probes to search by instruction slot*/
	struct hlist_node				is_hlist;
	/* list of kprobes for multi-handler support */
	struct list_head				list;
	/* Indicates that the corresponding module has been ref counted */
	unsigned int					mod_refcounted;
	/*count the number of times this probe was temporarily disarmed */
	unsigned long					nmissed;
	/* location of the probe point */
	kprobe_opcode_t					*addr;
	/* Allow user to indicate symbol name of the probe point */
	char						*symbol_name;
	/* Offset into the symbol */
	unsigned int					offset;
	/* Called before addr is executed. */
	kprobe_pre_handler_t				pre_handler;
	/* Called after addr is executed, unless... */
	kprobe_post_handler_t				post_handler;
	/* ... called if executing addr causes a fault (eg. page fault).
	 * Return 1 if it handled fault, otherwise kernel will see it. */
	kprobe_fault_handler_t				fault_handler;
	/* ... called if breakpoint trap occurs in probe handler.
	 * Return 1 if it handled break, otherwise kernel will see it. */
	kprobe_break_handler_t				break_handler;
	/* Saved opcode (which has been replaced with breakpoint) */
	kprobe_opcode_t					opcode;
	/* copy of the original instruction */
	struct arch_specific_insn			ainsn;
	// override single-step target address,
	// may be used to redirect control-flow to arbitrary address after probe point
	// without invocation of original instruction;
	// useful for functions replacement
	// if jprobe.entry should return address of function or NULL
	// if original function should be called
	// not supported for X86, not tested for MIPS
	kprobe_opcode_t					*ss_addr[NR_CPUS];
	// safe/unsafe to use probe
#ifdef CONFIG_ARM
	unsigned					safe_arm:1;
	unsigned					safe_thumb:1;
#endif
};

typedef unsigned long (*kprobe_pre_entry_handler_t) (void *priv_arg, struct pt_regs * regs);

/*
 * Special probe type that uses setjmp-longjmp type tricks to resume
 * execution at a specified entry with a matching prototype corresponding
 * to the probed function - a trick to enable arguments to become
 * accessible seamlessly by probe handling logic.
 * Note:
 * Because of the way compilers allocate stack space for local variables
 * etc upfront, regardless of sub-scopes within a function, this mirroring
 * principle currently works only for probes placed on function entry points.
 */
struct jprobe
{
	struct kprobe kp;
	// probe handling code to jump to
	kprobe_opcode_t *entry;
	// handler whichw willb bec called before 'entry'
	kprobe_pre_entry_handler_t pre_entry;
	void *priv_arg;
};

struct jprobe_instance
{
	// either on free list or used list
	struct hlist_node uflist;
	struct hlist_node hlist;
	struct jprobe *jp;
	struct task_struct *task;
};





/*
 * Function-return probe -
 * Note:
 * User needs to provide a handler function, and initialize maxactive.
 * maxactive - The maximum number of instances of the probed function that
 * can be active concurrently.
 * nmissed - tracks the number of times the probed function's return was
 * ignored, due to maxactive being too low.
 *
 */
struct kretprobe
{
	struct kprobe kp;
	kretprobe_handler_t handler;
	kretprobe_handler_t entry_handler;
	int maxactive;
	int nmissed;
	size_t data_size;
	struct hlist_head free_instances;
	struct hlist_head used_instances;

#ifdef CONFIG_ARM
	// probe with noreturn (bl,blx)
	unsigned					arm_noret:1;
	unsigned					thumb_noret:1;
#endif

};

struct kretprobe_instance
{
	// either on free list or used list
	struct hlist_node uflist;
	struct hlist_node hlist;
	struct kretprobe *rp;
	unsigned long *ret_addr;
	unsigned long *sp;
	struct task_struct *task;
	char data[0];
};


extern void kprobes_inc_nmissed_count (struct kprobe *p);

//
// Large value for fast but memory consuming implementation
// it is good when a lot of probes are instrumented
//
//#define KPROBE_HASH_BITS 6
#define KPROBE_HASH_BITS 16
#define KPROBE_TABLE_SIZE (1 << KPROBE_HASH_BITS)


/* Get the kprobe at this addr (if any) - called with preemption disabled */
struct kprobe *get_kprobe(void *addr);


int dbi_register_kprobe (struct kprobe *p);
void dbi_unregister_kprobe(struct kprobe *p);

int setjmp_pre_handler (struct kprobe *, struct pt_regs *);
int longjmp_break_handler (struct kprobe *, struct pt_regs *);

int dbi_register_jprobe (struct jprobe *p);
void dbi_unregister_jprobe (struct jprobe *p);
void dbi_jprobe_return (void);


int dbi_register_kretprobe (struct kretprobe *rp);
void dbi_unregister_kretprobe (struct kretprobe *rp);
void dbi_unregister_kretprobes(struct kretprobe **rpp, size_t size);

/*
 * use:
 *	dbi_unregister_kretprobe[s]_top();
 *	synchronize_sched();
 *	dbi_unregister_kretprobe[s]_bottom();
 *
 * rp_disarm - indicates the need for restoration of the return address
 */
void dbi_unregister_kretprobe_top(struct kretprobe *rp, int rp_disarm);
void dbi_unregister_kretprobes_top(struct kretprobe **rps, size_t size,
				   int rp_disarm);
void dbi_unregister_kretprobe_bottom(struct kretprobe *rp);
void dbi_unregister_kretprobes_bottom(struct kretprobe **rps, size_t size);


int dbi_disarm_urp_inst_for_task(struct task_struct *parent, struct task_struct *task);

int trampoline_probe_handler (struct kprobe *p, struct pt_regs *regs);


extern DEFINE_PER_CPU (struct kprobe *, current_kprobe);
extern struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];
//extern struct hlist_head kretprobe_inst_table[KPROBE_TABLE_SIZE];
extern atomic_t kprobe_count;
extern unsigned long sched_addr;

struct kprobe *kprobe_running (void);
void reset_current_kprobe (void);
struct kprobe_ctlblk *get_kprobe_ctlblk (void);

void prepare_singlestep(struct kprobe *p, struct pt_regs *regs);

#endif /* _DBI_KPROBES_H */

