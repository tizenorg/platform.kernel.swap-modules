// src_asm_kprobes.h
#ifndef _SRC_ASM_KPROBES_H
#define _SRC_ASM_KPROBES_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif

//#define _DEBUG
//#define KPROBES_RET_PROBE_TRAMP
//#define KPROBES_PROFILE	


#ifdef _DEBUG
extern int gSilent;
#define DBPRINTF(format, args...) do { \
		if( !gSilent ){ \
			char *f = __FILE__; \
			char *n = strrchr(f, '/'); \
			printk("%s : %u : %s : " format "\n" , (n) ? n+1 : f, __LINE__, __FUNCTION__, ##args); \
		} \
	} while(0)
#else
#define DBPRINTF(format, args...)
#endif

#if defined(CONFIG_MIPS)
typedef unsigned long kprobe_opcode_t;
# define BREAKPOINT_INSTRUCTION	0x0000000d
# ifndef KPROBES_RET_PROBE_TRAMP
#  define UNDEF_INSTRUCTION		0x0000004d
# endif
#elif defined(CONFIG_ARM)
typedef unsigned long kprobe_opcode_t;
# ifdef CONFIG_CPU_S3C2443
#  define BREAKPOINT_INSTRUCTION	0xe1200070
# else
#  define BREAKPOINT_INSTRUCTION	0xffffffff
# endif
# ifndef KPROBES_RET_PROBE_TRAMP
#  ifdef CONFIG_CPU_S3C2443
#   define UNDEF_INSTRUCTION		0xe1200071
#  else
#   define UNDEF_INSTRUCTION		0xfffffffe
#  endif
# endif
#elif defined(CONFIG_X86)
typedef u8 kprobe_opcode_t;
# define BREAKPOINT_INSTRUCTION	0xcc
# define RELATIVEJUMP_INSTRUCTION 0xe9
/*# define UNDEF_INSTRUCTION	0xff
# warning UNDEF_INSTRUCTION is not defined for x86 arch!!!*/
#else
# error BREAKPOINT_INSTRUCTION is not defined for this arch!!!
# error UNDEF_INSTRUCTION is not defined for this arch!!!
#endif // ARCH

#if defined(CONFIG_X86)
# define MAX_INSN_SIZE 16
# define MAX_STACK_SIZE 64
# define MIN_STACK_SIZE(ADDR) (((MAX_STACK_SIZE) < \
	(((unsigned long)current_thread_info()) + THREAD_SIZE - (ADDR))) \
	? (MAX_STACK_SIZE) \
	: (((unsigned long)current_thread_info()) + THREAD_SIZE - (ADDR)))

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
# define EREG(rg)		e##rg
# define XREG(rg)		x##rg
# define ORIG_EAX_REG	orig_eax
#else
# define EREG(rg)		rg
# define XREG(rg)		rg
# define ORIG_EAX_REG	orig_ax
#endif
#else//non x86
# define MAX_INSN_SIZE 1
#endif

#define flush_insn_slot(p)	do { } while (0)

#define kprobe_lookup_name(name, addr)

/* Architecture specific copy of original instruction */
struct arch_specific_insn {
	/* copy of the original instruction */
	kprobe_opcode_t *insn;
	/*
	 * If this flag is not 0, this kprobe can be boost when its
	 * post_handler and break_handler is not set.
	 */
	int boostable;
};	

#define JPROBE_ENTRY(pentry)	(kprobe_opcode_t *)pentry

struct prev_kprobe {
	struct kprobe *kp;
	unsigned long status;
#if defined(CONFIG_X86)
	unsigned long old_eflags;
	unsigned long saved_eflags;
#endif
};

/* per-cpu kprobe control block */
struct kprobe_ctlblk {
	unsigned long kprobe_status;
	struct prev_kprobe prev_kprobe;
#if defined(CONFIG_X86)
	struct pt_regs jprobe_saved_regs;
	unsigned long kprobe_old_eflags;
	unsigned long kprobe_saved_eflags;
	unsigned long *jprobe_saved_esp;
	kprobe_opcode_t jprobes_stack[MAX_STACK_SIZE];
#endif
};

void kretprobe_trampoline (void);

extern int kprobe_handler (struct pt_regs *regs);
extern int page_present (struct mm_struct *mm, unsigned long addr);

#if defined(CONFIG_X86)
extern int kprobe_exceptions_notify (struct notifier_block *self, unsigned long val, void *data);
#endif // CONFIG_X86

#endif				/* _SRC_ASM_KPROBES_H */
