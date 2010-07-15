// src_kprobes.h
#ifndef _SRC_KPROBES_H
#define _SRC_KPROBES_H

#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
//#include <linux/mutex.h>
#include <linux/sched.h>

#include "asm/kprobes.h"

/* kprobe_status settings */
#define KPROBE_HIT_ACTIVE	0x00000001
#define KPROBE_HIT_SS		0x00000002
#define KPROBE_REENTER		0x00000004
#define KPROBE_HIT_SSDONE	0x00000008

/* Attach to insert probes on any functions which should be ignored*/
#define __kprobes	__attribute__((__section__(".kprobes.text")))

struct kprobe;
struct pt_regs;
struct kretprobe;
struct kretprobe_instance;
typedef int (*kprobe_pre_handler_t) (struct kprobe *, struct pt_regs *	/*, struct vm_area_struct **, 
									   struct page **, unsigned long ** */ );
typedef int (*kprobe_break_handler_t) (struct kprobe *, struct pt_regs *	/*, struct vm_area_struct **, 
										   struct page **, unsigned long ** */ );
typedef void (*kprobe_post_handler_t) (struct kprobe *, struct pt_regs *, unsigned long flags);
typedef int (*kprobe_fault_handler_t) (struct kprobe *, struct pt_regs *, int trapnr);
typedef int (*kretprobe_handler_t) (struct kretprobe_instance *, struct pt_regs *, void *);

struct kprobe
{
	struct hlist_node hlist;

	/*list of probes to search by instruction slot*/
	struct hlist_node is_hlist;

	/* list of kprobes for multi-handler support */
	struct list_head list;

	/* Indicates that the corresponding module has been ref counted */
	unsigned int mod_refcounted;

	/*count the number of times this probe was temporarily disarmed */
	unsigned long nmissed;

	/* location of the probe point */
	kprobe_opcode_t *addr;

	/* Allow user to indicate symbol name of the probe point */
	char *symbol_name;

	/* Offset into the symbol */
	unsigned int offset;

	/* Called before addr is executed. */
	kprobe_pre_handler_t pre_handler;

	/* Called after addr is executed, unless... */
	kprobe_post_handler_t post_handler;

	/* ... called if executing addr causes a fault (eg. page fault).
	 * Return 1 if it handled fault, otherwise kernel will see it. */
	kprobe_fault_handler_t fault_handler;

	/* ... called if breakpoint trap occurs in probe handler.
	 * Return 1 if it handled break, otherwise kernel will see it. */
	kprobe_break_handler_t break_handler;

	/* Saved opcode (which has been replaced with breakpoint) */
	kprobe_opcode_t opcode;

	/* copy of the original instruction */
	struct arch_specific_insn ainsn;
	// TGID to which probe belongs
	pid_t tgid;
	// override single-step target address,
	// may be used to redirect control-flow to arbitrary address after probe point
	// without invocation of original instruction;
	// useful for functions replacement
	// if jprobe.entry should return address of function or NULL
	// if original function should be called
	// not supported for X86, not tested for MIPS
	kprobe_opcode_t *ss_addr;
#ifdef _DEBUG
	unsigned long entry_count;
	unsigned long step_count;
	unsigned long exit_count;
	unsigned long lr;
#endif
#ifdef KPROBES_PROFILE
	struct timeval start_tm;
	struct timeval hnd_tm_sum;
	unsigned long count;
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
	kprobe_opcode_t *entry;	/* probe handling code to jump to */
	kprobe_pre_entry_handler_t pre_entry;	/*handler whichw willb bec called before 'entry' */
	void *priv_arg;
};

struct jprobe_instance
{
	struct hlist_node uflist;	/* either on free list or used list */
	struct hlist_node hlist;
	struct jprobe *jp;
	struct task_struct *task;
};

DECLARE_PER_CPU (struct kprobe *, current_kprobe);
DECLARE_PER_CPU (struct kprobe_ctlblk, kprobe_ctlblk);

extern void __arch_prepare_kretprobe (struct kretprobe *rp, struct pt_regs *regs);

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
	void *priv_arg;
	int maxactive;
	int nmissed;
	int disarm;
	struct hlist_head free_instances;
	struct hlist_head used_instances;
};

struct kretprobe_instance
{
	struct hlist_node uflist;	/* either on free list or used list */
	struct hlist_node hlist;
	struct kretprobe *rp;
	kprobe_opcode_t *ret_addr;
	struct kretprobe *rp2;
	struct task_struct *task;
};

extern spinlock_t kretprobe_lock;
extern struct mutex kprobe_mutex;
extern int arch_prepare_kprobe (struct kprobe *p);
extern int arch_prepare_uprobe (struct kprobe *p, struct task_struct *task, int atomic);
extern int arch_prepare_kretprobe (struct kretprobe *p);
extern int arch_prepare_uretprobe (struct kretprobe *p, struct task_struct *task);
extern void arch_arm_kprobe (struct kprobe *p);
extern void arch_arm_kretprobe (struct kretprobe *p);
extern void arch_arm_uprobe (struct kprobe *p, struct task_struct *tsk);
extern void arch_arm_uretprobe (struct kretprobe *p, struct task_struct *tsk);
extern void arch_disarm_kprobe (struct kprobe *p);
extern void arch_disarm_kretprobe (struct kretprobe *p);
extern void arch_disarm_uprobe (struct kprobe *p, struct task_struct *tsk);
extern void arch_disarm_uretprobe (struct kretprobe *p, struct task_struct *tsk);
extern int arch_init_kprobes (void);
extern void arch_exit_kprobes (void);
extern void show_registers (struct pt_regs *regs);
extern void kprobes_inc_nmissed_count (struct kprobe *p);

/* Get the kprobe at this addr (if any) - called with preemption disabled */
struct kprobe *get_kprobe (void *addr, int pid, struct task_struct *ctask);
struct kprobe *get_kprobe_by_insn_slot (void *addr, int tgid, struct task_struct *ctask);
struct hlist_head *kretprobe_inst_table_head (struct task_struct *tsk);

/* kprobe_running() will just return the current_kprobe on this CPU */
static inline struct kprobe *
kprobe_running (void)
{
	return (__get_cpu_var (current_kprobe));
}

static inline void
reset_current_kprobe (void)
{
	//__get_cpu_var (current_kprobe)->spid = -1;
	__get_cpu_var (current_kprobe) = NULL;
}

static inline struct kprobe_ctlblk *
get_kprobe_ctlblk (void)
{
	return (&__get_cpu_var (kprobe_ctlblk));
}

int register_kprobe (struct kprobe *p, int atomic);
void unregister_kprobe (struct kprobe *p, struct task_struct *task, int atomic);
int setjmp_pre_handler (struct kprobe *, struct pt_regs *);
int longjmp_break_handler (struct kprobe *, struct pt_regs *);
int register_jprobe (struct jprobe *p, int atomic);
void unregister_jprobe (struct jprobe *p, int atomic);
int register_ujprobe (struct task_struct *task, struct mm_struct *mm, struct jprobe *jp, int atomic);
void unregister_ujprobe (struct task_struct *task, struct jprobe *jp, int atomic);
void unregister_uprobe (struct kprobe *p, struct task_struct *task, int atomic);
void jprobe_return (void);
void uprobe_return (void);

int register_kretprobe (struct kretprobe *rp, int atomic);
void unregister_kretprobe (struct kretprobe *rp, int atomic);
int register_uretprobe (struct task_struct *task, struct mm_struct *mm, struct kretprobe *rp, int atomic);
void unregister_uretprobe (struct task_struct *task, struct kretprobe *rp, int atomic);

void unregister_all_uprobes (struct task_struct *task, int atomic);

struct kretprobe_instance *get_free_rp_inst (struct kretprobe *rp);
void add_rp_inst (struct kretprobe_instance *ri);
//void kprobe_flush_task(struct task_struct *tk);
void recycle_rp_inst (struct kretprobe_instance *ri, struct hlist_head *head);

//void arch_copy_kprobe(struct kprobe *p);
void arch_remove_kprobe (struct kprobe *p, struct task_struct *task);
void kretprobe_trampoline_holder (void);
int __kprobes trampoline_probe_handler (struct kprobe *p, struct pt_regs *regs);
#ifdef KPROBES_PROFILE
int __kprobes pre_handler_kretprobe (struct kprobe *p, struct pt_regs *regs, struct vm_area_struct **vma, struct page **page, unsigned long **kaddr);
void set_normalized_timeval (struct timeval *tv, time_t sec, suseconds_t usec);
#endif

kprobe_opcode_t *get_insn_slot (struct task_struct *task, int atomic);
void free_insn_slot (struct hlist_head *page_list, struct task_struct *task, kprobe_opcode_t *slot, int dirty);

int access_process_vm_atomic(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);

#define read_proc_vm_atomic(tsk, addr, buf, len)	access_process_vm_atomic(tsk, addr, buf, len, 0)
#define write_proc_vm_atomic(tsk, addr, buf, len)	access_process_vm_atomic(tsk, addr, buf, len, 1)
int page_present (struct mm_struct *mm, unsigned long addr);
/*int get_user_pages_atomic(struct task_struct *tsk, struct mm_struct *mm,
		                unsigned long start, int len, int write, int force,
		                struct page **pages, struct vm_area_struct **vmas);*/
#define get_user_pages_atomic 	get_user_pages
#ifdef KERNEL_HAS_ISPAGEPRESENT
#define page_present 			is_page_present
#else
int page_present (struct mm_struct *mm, unsigned long addr);
#endif
void purge_garbage_uslots(struct task_struct *task, int atomic);
#endif /* _SRC_KPROBES_H */

extern kprobe_opcode_t *sched_addr;
extern kprobe_opcode_t *fork_addr;
