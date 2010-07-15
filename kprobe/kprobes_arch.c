#include <linux/version.h>	// LINUX_VERSION_CODE, KERNEL_VERSION()
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>
#include <linux/module.h>
#include <linux/highmem.h>	// kmap_atomic, kunmap_atomic, copy_from_user_page, copy_to_user_page
#include <linux/pagemap.h>	// page_cache_release
#include <asm/system.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/mman.h>
#include <linux/personality.h>
#include <linux/hugetlb.h>
#include <linux/file.h>
#include <linux/mempolicy.h>
#if defined(CONFIG_X86)
#include <linux/kdebug.h>
#include <linux/moduleloader.h>
#include <linux/freezer.h>
#include <linux/hardirq.h>
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 19))
#include <linux/freezer.h>
#endif

#include "kprobes.h"

#if defined(CONFIG_X86)
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
#  define TF_MASK	X86_EFLAGS_TF
#  define IF_MASK	X86_EFLAGS_IF
# endif
# define UPROBES_TRAMP_LEN				(MAX_INSN_SIZE+sizeof(kprobe_opcode_t))
# define UPROBES_TRAMP_INSN_IDX			0
# define UPROBES_TRAMP_RET_BREAK_IDX	MAX_INSN_SIZE
# define KPROBES_TRAMP_LEN				MAX_INSN_SIZE
# define KPROBES_TRAMP_INSN_IDX			0
#elif defined(CONFIG_ARM) 
# define UPROBES_TRAMP_LEN				8
# define UPROBES_TRAMP_INSN_IDX			2
# define UPROBES_TRAMP_SS_BREAK_IDX		4
# define UPROBES_TRAMP_RET_BREAK_IDX	5
# define KPROBES_TRAMP_LEN				8
# define KPROBES_TRAMP_INSN_IDX			UPROBES_TRAMP_INSN_IDX
# define KPROBES_TRAMP_SS_BREAK_IDX		UPROBES_TRAMP_SS_BREAK_IDX
# define KPROBES_TRAMP_RET_BREAK_IDX	UPROBES_TRAMP_RET_BREAK_IDX
#elif defined(CONFIG_MIPS) 
# define UPROBES_TRAMP_LEN				3
# define UPROBES_TRAMP_INSN_IDX			0
# define UPROBES_TRAMP_SS_BREAK_IDX		1
# define UPROBES_TRAMP_RET_BREAK_IDX	2
# define KPROBES_TRAMP_LEN				UPROBES_TRAMP_LEN
# define KPROBES_TRAMP_INSN_IDX			UPROBES_TRAMP_INSN_IDX
# define KPROBES_TRAMP_SS_BREAK_IDX		UPROBES_TRAMP_SS_BREAK_IDX
# define KPROBES_TRAMP_RET_BREAK_IDX	UPROBES_TRAMP_RET_BREAK_IDX
#endif //CONFIG_MIPS

DEFINE_PER_CPU (struct kprobe *, current_kprobe) = NULL;
DEFINE_PER_CPU (struct kprobe_ctlblk, kprobe_ctlblk);

/* kprobe_status settings */
#define KPROBE_HIT_ACTIVE	0x00000001
#define KPROBE_HIT_SS		0x00000002

#define INVALID_VALUE 0xFFFFFFFF
#define INVALID_POINTER (void*)INVALID_VALUE

static int ksyms = INVALID_VALUE;
module_param (ksyms, int, 0);

extern unsigned long handled_exceptions;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 12))
#define synchronize_sched	synchronize_kernel
#endif

void jprobe_return_end (void);
void uprobe_return_end (void);

#if defined(CONFIG_X86)
/*fastcall*/ void *__kprobes trampoline_probe_handler_x86 (struct pt_regs *regs);
#endif

static inline void
kretprobe_assert (struct kretprobe_instance *ri, unsigned long orig_ret_address, unsigned long trampoline_address)
{
	if (!orig_ret_address || (orig_ret_address == trampoline_address))
		panic ("kretprobe BUG!: Processing kretprobe %p @ %p\n", ri->rp, ri->rp->kp.addr);
}

#define HIWORD(x) (((x) & 0xFFFF0000) >> 16)
#define LOWORD(x) ((x) & 0x0000FFFF)

unsigned int gl_nNumberOfInstructions = 0;
unsigned int gl_nCodeSize = 0;

unsigned int arrTrapsTemplate[] = {
#if defined(CONFIG_MIPS)
		0x3c010000,		// lui  a1                              [0]
		0x24210000,		// addiu a1, a1                         [1]
		0x00200008,		// jr a1                                [2]
		0x00000000,		// nop
		0xffffffff		// end
#elif defined(CONFIG_ARM)
		0xe1a0c00d,		// mov          ip, sp
		0xe92dd800,		// stmdb    sp!, {fp, ip, lr, pc}
		0xe24cb004,		// sub          fp, ip, #4      ; 0x4
		0x00000000,		// b                                    [3]
		0xe3500000,		// cmp          r0, #0  ; 0x0   
		0xe89da800,		// ldmia        sp, {fp, sp, pc}
		0x00000000,		// nop
		0xffffffff		// end
#endif // ARCH
};

unsigned long nCount;

kprobe_opcode_t *sched_addr;
kprobe_opcode_t *fork_addr;

#if defined(CONFIG_MIPS)
#define REG_HI_INDEX 0
#define REG_LO_INDEX 1
#define NOTIFIER_CALL_CHAIN_INDEX 0

#elif defined(CONFIG_ARM)
#define NOTIFIER_CALL_CHAIN_INDEX 3
//#define NOTIFIER_CALL_CHAIN_INDEX1 6
//#define NOTIFIER_CALL_CHAIN_INDEX2 11

static unsigned int
arch_construct_brunch (unsigned int base, unsigned int addr, int link)
{
	kprobe_opcode_t insn;
	unsigned int bpi = (unsigned int) base - (unsigned int) addr - 8;
	insn = bpi >> 2;
	DBPRINTF ("base=%x addr=%x base-addr-8=%x\n", base, addr, bpi);
	if (abs (insn & 0xffffff) > 0xffffff)
	{
		DBPRINTF ("ERROR: kprobe address out of range\n");
		BUG ();
	}
	insn = insn & 0xffffff;
	insn = insn | ((link != 0) ? 0xeb000000 : 0xea000000);
	DBPRINTF ("insn=%lX\n", insn);
	return (unsigned int) insn;
}
#endif // ARCH

unsigned int *arrTrapsOriginal = NULL;

#ifndef KERNEL_HAS_ISPAGEPRESENT
int
page_present (struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	int ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 11)
	pud_t *pud;
#endif

	//printk("page_present\n");
	//BUG_ON(down_read_trylock(&mm->mmap_sem) == 0);
	down_read (&mm->mmap_sem);
	spin_lock (&(mm->page_table_lock));
	pgd = pgd_offset (mm, addr);
	//printk("pgd %p\n", pgd);
	if ((pgd != NULL) && pgd_present (*pgd))
	{
		//printk("pgd_present\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 11)
		pud = pud_offset (pgd, addr);
		//printk("pud %p\n", pud);
		if ((pud != NULL) && pud_present (*pud))
		{
			pmd = pmd_offset (pud, addr);
#else
		{
			pmd = pmd_offset (pgd, addr);
#endif
			//printk("pmd %p\n", pmd);
			if ((pmd != NULL) && pmd_present (*pmd))
			{
				//spinlock_t *ptl;
				//printk("pmd_present\n");
				pte = pte_offset_map (pmd, addr);
				//pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
				//printk("pte %p/%lx\n", pte, addr);
				if ((pte != NULL) && pte_present (*pte))
				{
					ret = 1;
					//printk("pte_present\n");
				}
				pte_unmap (pte);
				//pte_unmap_unlock(pte, ptl);
			}
		}
	}
	spin_unlock (&(mm->page_table_lock));
	up_read (&mm->mmap_sem);
	//printk("page_present %d\n", ret);
	return ret;
}
#endif

#if defined(CONFIG_MIPS)
#define MIPS_INSN_OPCODE_MASK	0xFC000000
#define MIPS_INSN_RS_MASK		0x03E00000
#define MIPS_INSN_RT_MASK		0x001F0000
//#define MIPS_INSN_UN_MASK             0x0000FFC0
#define MIPS_INSN_FUNC_MASK		0x0000003F
#define MIPS_INSN_OPCODE(insn)	(insn & MIPS_INSN_OPCODE_MASK)
#define MIPS_INSN_RS(insn)		(insn & MIPS_INSN_RS_MASK)
#define MIPS_INSN_RT(insn)		(insn & MIPS_INSN_RT_MASK)
#define MIPS_INSN_FUNC(insn)	(insn & MIPS_INSN_FUNC_MASK)
// opcodes 31..26
#define MIPS_BEQ_OPCODE		0x10000000
#define MIPS_BNE_OPCODE		0x14000000
#define MIPS_BLEZ_OPCODE	0x18000000
#define MIPS_BGTZ_OPCODE	0x1C000000
#define MIPS_BEQL_OPCODE	0x50000000
#define MIPS_BNEL_OPCODE	0x54000000
#define MIPS_BLEZL_OPCODE	0x58000000
#define MIPS_BGTZL_OPCODE	0x5C000000
#define MIPS_REGIMM_OPCODE	0x04000000
#define MIPS_SPECIAL_OPCODE	0x00000000
#define MIPS_COP1_OPCODE	0x44000000
#define MIPS_COP2_OPCODE	0x48000000
#define MIPS_J_OPCODE		0x08000000
#define MIPS_JAL_OPCODE		0x0C000000
#define MIPS_JALX_OPCODE	0x74000000
// rs 25..21
#define MIPS_BC_RS			0x01000000
// rt 20..16
#define MIPS_BLTZ_RT		0x00000000
#define MIPS_BGEZ_RT		0x00010000
#define MIPS_BLTZL_RT		0x00020000
#define MIPS_BGEZL_RT		0x00030000
#define MIPS_BLTZAL_RT		0x00100000
#define MIPS_BGEZAL_RT		0x00110000
#define MIPS_BLTZALL_RT		0x00120000
#define MIPS_BGEZALL_RT		0x00130000
// unnamed 15..6
// function 5..0
#define MIPS_JR_FUNC		0x00000008
#define MIPS_JALR_FUNC		0x00000009
#define MIPS_BREAK_FUNC		0x0000000D
#define MIPS_SYSCALL_FUNC	0x0000000C

#elif defined(CONFIG_ARM)
// undefined
#define MASK_ARM_INSN_UNDEF		0x0FF00000
#define PTRN_ARM_INSN_UNDEF		0x03000000
// architecturally undefined
#define MASK_ARM_INSN_AUNDEF	0x0FF000F0
#define PTRN_ARM_INSN_AUNDEF	0x07F000F0
// branches
#define MASK_ARM_INSN_B			0x0E000000
#define PTRN_ARM_INSN_B			0x0A000000
#define MASK_ARM_INSN_BL		0x0E000000
#define PTRN_ARM_INSN_BL		0x0B000000
#define MASK_ARM_INSN_BLX1		0xFF000000
#define PTRN_ARM_INSN_BLX1		0xFA000000
#define MASK_ARM_INSN_BLX2		0x0FF000F0
#define PTRN_ARM_INSN_BLX2		0x01200030
#define MASK_ARM_INSN_BX		0x0FF000F0
#define PTRN_ARM_INSN_BX		0x01200010
#define MASK_ARM_INSN_BXJ		0x0FF000F0
#define PTRN_ARM_INSN_BXJ		0x01200020
// software interrupts
#define MASK_ARM_INSN_SWI		0x0F000000
#define PTRN_ARM_INSN_SWI		0x0F000000
// break
#define MASK_ARM_INSN_BREAK		0xFFF000F0
#define PTRN_ARM_INSN_BREAK		0xE1200070
// Data processing immediate shift
#define MASK_ARM_INSN_DPIS		0x0E000010
#define PTRN_ARM_INSN_DPIS		0x00000000
// Data processing register shift
#define MASK_ARM_INSN_DPRS		0x0E000090
#define PTRN_ARM_INSN_DPRS		0x00000010
// Data processing immediate
#define MASK_ARM_INSN_DPI		0x0E000000
#define PTRN_ARM_INSN_DPI		0x02000000
// Load immediate offset
#define MASK_ARM_INSN_LIO		0x0E100000
#define PTRN_ARM_INSN_LIO		0x04100000
// Store immediate offset
#define MASK_ARM_INSN_SIO		MASK_ARM_INSN_LIO
#define PTRN_ARM_INSN_SIO		0x04000000
// Load register offset
#define MASK_ARM_INSN_LRO		0x0E100010
#define PTRN_ARM_INSN_LRO		0x06100000
// Store register offset
#define MASK_ARM_INSN_SRO		MASK_ARM_INSN_LRO
#define PTRN_ARM_INSN_SRO		0x06000000
// Load multiple
#define MASK_ARM_INSN_LM		0x0E100000
#define PTRN_ARM_INSN_LM		0x08100000
// Store multiple
#define MASK_ARM_INSN_SM		MASK_ARM_INSN_LM
#define PTRN_ARM_INSN_SM		0x08000000
// Coprocessor load/store and double register transfers
#define MASK_ARM_INSN_CLS		0x0E000000
#define PTRN_ARM_INSN_CLS		0x0C000000
// Coprocessor register transfers
#define MASK_ARM_INSN_CRT		0x0F000010
#define PTRN_ARM_INSN_CRT		0x0E000010

#define ARM_INSN_MATCH(name, insn)	((insn & MASK_ARM_INSN_##name) == PTRN_ARM_INSN_##name)

#define ARM_INSN_REG_RN(insn)			((insn & 0x000F0000)>>16)
#define ARM_INSN_REG_SET_RN(insn, nreg)	{insn &= ~0x000F0000; insn |= nreg<<16;}
#define ARM_INSN_REG_RD(insn)			((insn & 0x0000F000)>>12)
#define ARM_INSN_REG_SET_RD(insn, nreg)	{insn &= ~0x0000F000; insn |= nreg<<12;}
#define ARM_INSN_REG_RS(insn)			((insn & 0x00000F00)>>8)
#define ARM_INSN_REG_SET_RS(insn, nreg)	{insn &= ~0x00000F00; insn |= nreg<<8;}
#define ARM_INSN_REG_RM(insn)			(insn & 0x0000000F)
#define ARM_INSN_REG_SET_RM(insn, nreg)	{insn &= ~0x0000000F; insn |= nreg;}
#define ARM_INSN_REG_MR(insn, nreg)		(insn & (1 << nreg))
#define ARM_INSN_REG_SET_MR(insn, nreg)	{insn |= (1 << nreg);}
#define ARM_INSN_REG_CLEAR_MR(insn, nreg)	{insn &= ~(1 << nreg);}

#elif defined(CONFIG_X86)
//#	warning Branch instruction patterns are not defined for x86 arch!!!
#endif

#if defined(CONFIG_X86)
/* insert a jmp code */
static __always_inline void
set_jmp_op (void *from, void *to)
{
	struct __arch_jmp_op
	{
		char op;
		long raddr;
	} __attribute__ ((packed)) * jop;
	jop = (struct __arch_jmp_op *) from;
	jop->raddr = (long) (to) - ((long) (from) + 5);
	jop->op = RELATIVEJUMP_INSTRUCTION;
}

static void
set_user_jmp_op (void *from, void *to)
{
	struct __arch_jmp_op
	{
		char op;
		long raddr;
	} __attribute__ ((packed)) jop;
	//jop = (struct __arch_jmp_op *) from;
	jop.raddr = (long) (to) - ((long) (from) + 5);
	jop.op = RELATIVEJUMP_INSTRUCTION;
	if (!write_proc_vm_atomic (current, (unsigned long)from, &jop, sizeof(jop)))
		panic ("failed to write jump opcode to user space %p!\n", from);	
}

/*
 * returns non-zero if opcodes can be boosted.
 */
static __always_inline int
can_boost (kprobe_opcode_t * opcodes)
{
#define W(row,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf)		      \
	(((b0##UL << 0x0)|(b1##UL << 0x1)|(b2##UL << 0x2)|(b3##UL << 0x3) |   \
	  (b4##UL << 0x4)|(b5##UL << 0x5)|(b6##UL << 0x6)|(b7##UL << 0x7) |   \
	  (b8##UL << 0x8)|(b9##UL << 0x9)|(ba##UL << 0xa)|(bb##UL << 0xb) |   \
	  (bc##UL << 0xc)|(bd##UL << 0xd)|(be##UL << 0xe)|(bf##UL << 0xf))    \
	 << (row % 32))
	/*
	 * Undefined/reserved opcodes, conditional jump, Opcode Extension
	 * Groups, and some special opcodes can not be boost.
	 */
	static const unsigned long twobyte_is_boostable[256 / 32] = {
		/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
		/*      -------------------------------         */
		W (0x00, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0) |	/* 00 */
			W (0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),	/* 10 */
		W (0x20, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) |	/* 20 */
			W (0x30, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),	/* 30 */
		W (0x40, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) |	/* 40 */
			W (0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),	/* 50 */
		W (0x60, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1) |	/* 60 */
			W (0x70, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1),	/* 70 */
		W (0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) |	/* 80 */
			W (0x90, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1),	/* 90 */
		W (0xa0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1) |	/* a0 */
			W (0xb0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1),	/* b0 */
		W (0xc0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1) |	/* c0 */
			W (0xd0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1),	/* d0 */
		W (0xe0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1) |	/* e0 */
			W (0xf0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0)	/* f0 */
			/*      -------------------------------         */
			/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	};
#undef W
	kprobe_opcode_t opcode;
	kprobe_opcode_t *orig_opcodes = opcodes;
      retry:
	if (opcodes - orig_opcodes > MAX_INSN_SIZE - 1)
		return 0;
	opcode = *(opcodes++);

	/* 2nd-byte opcode */
	if (opcode == 0x0f)
	{
		if (opcodes - orig_opcodes > MAX_INSN_SIZE - 1)
			return 0;
		return test_bit (*opcodes, twobyte_is_boostable);
	}

	switch (opcode & 0xf0)
	{
	case 0x60:
		if (0x63 < opcode && opcode < 0x67)
			goto retry;	/* prefixes */
		/* can't boost Address-size override and bound */
		return (opcode != 0x62 && opcode != 0x67);
	case 0x70:
		return 0;	/* can't boost conditional jump */
	case 0xc0:
		/* can't boost software-interruptions */
		return (0xc1 < opcode && opcode < 0xcc) || opcode == 0xcf;
	case 0xd0:
		/* can boost AA* and XLAT */
		return (opcode == 0xd4 || opcode == 0xd5 || opcode == 0xd7);
	case 0xe0:
		/* can boost in/out and absolute jmps */
		return ((opcode & 0x04) || opcode == 0xea);
	case 0xf0:
		if ((opcode & 0x0c) == 0 && opcode != 0xf1)
			goto retry;	/* lock/rep(ne) prefix */
		/* clear and set flags can be boost */
		return (opcode == 0xf5 || (0xf7 < opcode && opcode < 0xfe));
	default:
		if (opcode == 0x26 || opcode == 0x36 || opcode == 0x3e)
			goto retry;	/* prefixes */
		/* can't boost CS override and call */
		return (opcode != 0x2e && opcode != 0x9a);
	}
}

/*
 * returns non-zero if opcode modifies the interrupt flag.
 */
static int __kprobes
is_IF_modifier (kprobe_opcode_t opcode)
{
	switch (opcode)
	{
	case 0xfa:		/* cli */
	case 0xfb:		/* sti */
	case 0xcf:		/* iret/iretd */
	case 0x9d:		/* popf/popfd */
		return 1;
	}
	return 0;
}
#endif

static int
arch_check_insn (struct arch_specific_insn *ainsn)
{
	int ret = 0;

#if defined(CONFIG_MIPS)
	switch (MIPS_INSN_OPCODE (ainsn->insn[0]))
	{
	case MIPS_BEQ_OPCODE:	//B, BEQ   
	case MIPS_BEQL_OPCODE:	//BEQL    
	case MIPS_BNE_OPCODE:	//BNE      
	case MIPS_BNEL_OPCODE:	//BNEL    
	case MIPS_BGTZ_OPCODE:	//BGTZ    
	case MIPS_BGTZL_OPCODE:	//BGTZL
	case MIPS_BLEZ_OPCODE:	//BLEZ    
	case MIPS_BLEZL_OPCODE:	//BLEZL  
	case MIPS_J_OPCODE:	//J  
	case MIPS_JAL_OPCODE:	//JAL
		DBPRINTF ("arch_check_insn: opcode");
		ret = -EFAULT;
		break;
	case MIPS_REGIMM_OPCODE:
		//BAL, BGEZ, BGEZAL, BGEZALL, BGEZL, BLTZ, BLTZAL, BLTZALL, BLTZL
		switch (MIPS_INSN_RT (ainsn->insn[0]))
		{
		case MIPS_BLTZ_RT:
		case MIPS_BGEZ_RT:
		case MIPS_BLTZL_RT:
		case MIPS_BGEZL_RT:
		case MIPS_BLTZAL_RT:
		case MIPS_BGEZAL_RT:
		case MIPS_BLTZALL_RT:
		case MIPS_BGEZALL_RT:
			DBPRINTF ("arch_check_insn: REGIMM opcode\n");
			ret = -EFAULT;
			break;
		}
		break;
		//BC1F, BC1FL, BC1T, BC1TL
	case MIPS_COP1_OPCODE:
		//BC2F, BC2FL, BC2T, BC2TL
	case MIPS_COP2_OPCODE:
		if (MIPS_INSN_RS (ainsn->insn[0]) == MIPS_BC_RS)
		{
			DBPRINTF ("arch_check_insn: COP1 opcode\n");
			ret = -EFAULT;
		}
		break;
	case MIPS_SPECIAL_OPCODE:
		//BREAK, JALR, JALR.HB, JR, JR.HB
		switch (MIPS_INSN_FUNC (ainsn->insn[0]))
		{
		case MIPS_JR_FUNC:
		case MIPS_JALR_FUNC:
		case MIPS_BREAK_FUNC:
		case MIPS_SYSCALL_FUNC:
			DBPRINTF ("arch_check_insn: SPECIAL opcode\n");
			ret = -EFAULT;
			break;
		}
		break;
	}
#elif defined(CONFIG_ARM)
	// check instructions that can change PC by nature 
	if (ARM_INSN_MATCH (UNDEF, ainsn->insn[0]) ||
	    ARM_INSN_MATCH (AUNDEF, ainsn->insn[0]) ||
	    ARM_INSN_MATCH (SWI, ainsn->insn[0]) ||
	    ARM_INSN_MATCH (BREAK, ainsn->insn[0]) ||
	    ARM_INSN_MATCH (B, ainsn->insn[0]) ||
	    ARM_INSN_MATCH (BL, ainsn->insn[0]) ||
	    ARM_INSN_MATCH (BLX1, ainsn->insn[0]) || 
	    ARM_INSN_MATCH (BLX2, ainsn->insn[0]) || 
	    ARM_INSN_MATCH (BX, ainsn->insn[0]) || 
	    ARM_INSN_MATCH (BXJ, ainsn->insn[0]))
	{
		DBPRINTF ("arch_check_insn: %lx\n", ainsn->insn[0]);
		ret = -EFAULT;
	}
#ifndef CONFIG_CPU_V7
	// check instructions that can write result to PC
	else if ((ARM_INSN_MATCH (DPIS, ainsn->insn[0]) ||
			  ARM_INSN_MATCH (DPRS, ainsn->insn[0]) ||
	          ARM_INSN_MATCH (DPI, ainsn->insn[0]) || 
	          ARM_INSN_MATCH (LIO, ainsn->insn[0]) || 
	          ARM_INSN_MATCH (LRO, ainsn->insn[0])) && 
	         (ARM_INSN_REG_RD (ainsn->insn[0]) == 15))
	{
		DBPRINTF ("arch_check_insn: %lx\n", ainsn->insn[0]);
		ret = -EFAULT;
	}
#endif // CONFIG_CPU_V7
	// check special instruction loads store multiple registers
	else if ((ARM_INSN_MATCH (LM, ainsn->insn[0]) || ARM_INSN_MATCH (SM, ainsn->insn[0])) &&
	    // store pc or load to pc
	    (ARM_INSN_REG_MR (ainsn->insn[0], 15) ||
	     // store/load with pc update
	     ((ARM_INSN_REG_RN (ainsn->insn[0]) == 15) && (ainsn->insn[0] & 0x200000))))
	{
		DBPRINTF ("arch_check_insn: %lx\n", ainsn->insn[0]);
		ret = -EFAULT;
	}
#elif defined(CONFIG_X86)
//#	warning arch_check_insn is not implemented for x86 arch!!!
#endif

	return ret;
}

/*
 * kprobe->ainsn.insn points to the copy of the instruction to be
 * single-stepped. x86_64, POWER4 and above have no-exec support and
 * stepping on the instruction on a vmalloced/kmalloced/data page
 * is a recipe for disaster
 */
#define INSNS_PER_PAGE	(PAGE_SIZE/(MAX_INSN_SIZE * sizeof(kprobe_opcode_t)))

struct kprobe_insn_page
{
	struct hlist_node hlist;
	kprobe_opcode_t *insns;	/* Page of instruction slots */
	char *slot_used;//[INSNS_PER_PAGE];	
	int nused;
	int ngarbage;
	int tgid;
};

enum kprobe_slot_state
{
	SLOT_CLEAN = 0,
	SLOT_DIRTY = 1,
	SLOT_USED = 2,
};

static struct hlist_head kprobe_insn_pages;
static int kprobe_garbage_slots;
static struct hlist_head uprobe_insn_pages;
static int uprobe_garbage_slots;
static int collect_garbage_slots (struct hlist_head *page_list, struct task_struct *task);

void gen_insn_execbuf (void);
void pc_dep_insn_execbuf (void);
void gen_insn_execbuf_holder (void);
void pc_dep_insn_execbuf_holder (void);

void
gen_insn_execbuf_holder (void)
{
	asm volatile (".global gen_insn_execbuf\n" 
				"gen_insn_execbuf:\n" 
#if defined(CONFIG_ARM)
				"nop\n" 
				"nop\n" 
				"nop\n"	// original instruction
		      	"nop\n" 
				"ldr	pc, [pc, #4]\n" //ssbreak 
				"nop\n" //retbreak
				"nop\n" 
				"nop\n"); //stored PC-4(next insn addr)
#elif defined(CONFIG_MIPS)
				"nop\n"	// original instruction
				"nop\n" //ssbreak 
				"nop\n");//retbreak
#else
				"nop\n");//retbreak
#endif
}

#if defined(CONFIG_ARM)
/*void
pc_dep_uinsn_execbuf_holder (void)
{
	asm volatile (".global pc_dep_uinsn_execbuf\n" 
				"pc_dep_uinsn_execbuf:\n"
		      	"str	r0, [pc, #20]\n" 
			 	"ldr	r0, [pc, #12]\n" 
				"nop\n"	// instruction with replaced PC
		      	"ldr	r0, [pc, #8]\n"
				"nop\n"	// ssbreak
		      	"nop\n"	// retbreak
		      	"nop\n" // stored PC
				"nop\n");// stored Rx
}*/
/*
 * 0. push Rx on stack
 * 1. load address to Rx
 * 2. do insn using Rx
 * 3. pop Rx from stack
 * 4. BREAK1
 * 5. BREAK2
 * 6. stored PC
 * 7. stored PC-4(next insn addr)
 */
void
pc_dep_insn_execbuf_holder (void)
{
	asm volatile (".global pc_dep_insn_execbuf\n" 
				"pc_dep_insn_execbuf:\n"
		      	"str	r0, [sp, #-4]\n" 
			 	"ldr	r0, [pc, #12]\n" 
				"nop\n"	// instruction with replaced PC
		      	"ldr	r0, [sp, #-4]\n"
				"ldr	pc, [pc, #4]\n" //ssbreak
		      	"nop\n"	// retbreak
				"nop\n" // stored PC
				"nop\n");// stored PC-4 (next insn addr)
}

static int
prep_pc_dep_insn_execbuf (kprobe_opcode_t * insns, kprobe_opcode_t insn, int uregs)
{
	int i;

	if (uregs & 0x10)
	{
		int reg_mask = 0x1;
		//search in reg list
		for (i = 0; i < 13; i++, reg_mask <<= 1)
		{
			if (!(insn & reg_mask))
				break;
		}
	}
	else
	{
		for (i = 0; i < 13; i++)
		{
			//              DBPRINTF("prep_pc_dep_insn_execbuf: check R%d/%d, changing regs %x in %x", 
			//                              i, ARM_INSN_REG_RN(insn), uregs, insn);
			if ((uregs & 0x1) && (ARM_INSN_REG_RN (insn) == i))
				continue;
			if ((uregs & 0x2) && (ARM_INSN_REG_RD (insn) == i))
				continue;
			if ((uregs & 0x4) && (ARM_INSN_REG_RS (insn) == i))
				continue;
			if ((uregs & 0x8) && (ARM_INSN_REG_RM (insn) == i))
				continue;
			break;
		}
	}
	if (i == 13)
	{
		DBPRINTF ("there are no free register %x in insn %lx!", uregs, insn);
		return -EINVAL;
	}
	DBPRINTF ("prep_pc_dep_insn_execbuf: using R%d, changing regs %x", i, uregs);

	// set register to save
	ARM_INSN_REG_SET_RD (insns[0], i);
	// set register to load address to
	ARM_INSN_REG_SET_RD (insns[1], i);
	// set instruction to execute and patch it 
	if (uregs & 0x10)
	{
		ARM_INSN_REG_CLEAR_MR (insn, 15);
		ARM_INSN_REG_SET_MR (insn, i);
	}
	else
	{
		if ((uregs & 0x1) && (ARM_INSN_REG_RN (insn) == 15))
			ARM_INSN_REG_SET_RN (insn, i);
		if ((uregs & 0x2) && (ARM_INSN_REG_RD (insn) == 15))
			ARM_INSN_REG_SET_RD (insn, i);
		if ((uregs & 0x4) && (ARM_INSN_REG_RS (insn) == 15))
			ARM_INSN_REG_SET_RS (insn, i);
		if ((uregs & 0x8) && (ARM_INSN_REG_RM (insn) == 15))
			ARM_INSN_REG_SET_RM (insn, i);
	}
	insns[UPROBES_TRAMP_INSN_IDX] = insn;
	// set register to restore
	ARM_INSN_REG_SET_RD (insns[3], i);
	return 0;
}
#endif//ARM

int
arch_prepare_kprobe (struct kprobe *p)
{
#if !defined(CONFIG_X86)
	kprobe_opcode_t insns[KPROBES_TRAMP_LEN];
#endif
#if defined(CONFIG_ARM)
	int uregs, pc_dep;
#endif

	int ret = 0;
#if !defined(CONFIG_X86)
	if ((unsigned long) p->addr & 0x01)
	{
		DBPRINTF ("Attempt to register kprobe at an unaligned address\n");
		ret = -EINVAL;
	}
#endif
	/* XXX: Might be a good idea to check if p->addr is a valid
	 * kernel address as well... */

	if (!ret)
	{
		kprobe_opcode_t insn[MAX_INSN_SIZE];
		struct arch_specific_insn ainsn;
		/* insn: must be on special executable page on i386. */
		p->ainsn.insn = get_insn_slot (NULL, 0);
		if (!p->ainsn.insn)
			return -ENOMEM;
		memcpy (insn, p->addr, MAX_INSN_SIZE * sizeof (kprobe_opcode_t));
		ainsn.insn = insn;
		ret = arch_check_insn (&ainsn);
		if (!ret)
		{
			p->opcode = *p->addr;
#if defined(CONFIG_ARM)
			p->ainsn.boostable = 1;
			uregs = pc_dep = 0;
			// Rn, Rm ,Rd
			if (ARM_INSN_MATCH (DPIS, insn[0]) || ARM_INSN_MATCH (LRO, insn[0]) || 
				ARM_INSN_MATCH (SRO, insn[0]))
			{

				uregs = 0xb;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_REG_RM (insn[0]) == 15) || 
					(ARM_INSN_MATCH (SRO, insn[0]) && (ARM_INSN_REG_RD (insn[0]) == 15)))
				{

					DBPRINTF ("Unboostable insn %lx, DPIS/LRO/SRO\n", insn[0]);
					pc_dep = 1;
				}
			}
			// Rn ,Rd
			else if (ARM_INSN_MATCH (DPI, insn[0]) || ARM_INSN_MATCH (LIO, insn[0]) || 
					 ARM_INSN_MATCH (SIO, insn[0]))
			{

				uregs = 0x3;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_MATCH (SIO, insn[0]) && 
					(ARM_INSN_REG_RD (insn[0]) == 15)))
				{

					pc_dep = 1;
					DBPRINTF ("Unboostable insn %lx/%p/%d, DPI/LIO/SIO\n", insn[0], p, p->ainsn.boostable);
				}
			}
			// Rn, Rm, Rs                                   
			else if (ARM_INSN_MATCH (DPRS, insn[0]))
			{

				uregs = 0xd;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_REG_RM (insn[0]) == 15) || 
					(ARM_INSN_REG_RS (insn[0]) == 15))
				{

					pc_dep = 1;
					DBPRINTF ("Unboostable insn %lx, DPRS\n", insn[0]);
				}
			}
			// register list
			else if (ARM_INSN_MATCH (SM, insn[0]))
			{

				uregs = 0x10;
				if (ARM_INSN_REG_MR (insn[0], 15))
				{

					DBPRINTF ("Unboostable insn %lx, SM\n", insn[0]);
					pc_dep = 1;
				}
			}
			// check instructions that can write result to SP andu uses PC
			if (pc_dep  && (ARM_INSN_REG_RD (ainsn.insn[0]) == 13))
			{
				static int count;
				count++;
				//printk ("insn writes result to SP and uses PC: %lx/%d\n", ainsn.insn[0], count);
				free_insn_slot (&kprobe_insn_pages, NULL, p->ainsn.insn, 0);
				ret = -EFAULT;
			}
			else {
				if (uregs && pc_dep)
				{
					memcpy (insns, pc_dep_insn_execbuf, sizeof (insns));
					if (prep_pc_dep_insn_execbuf (insns, insn[0], uregs) != 0)
					{
						DBPRINTF ("failed to prepare exec buffer for insn %lx!", insn[0]);
						free_insn_slot (&kprobe_insn_pages, NULL, p->ainsn.insn, 0);
						return -EINVAL;
					}
					//insns[KPROBES_TRAMP_SS_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
					insns[6] = (kprobe_opcode_t) (p->addr + 2);
				}
				else
				{
					memcpy (insns, gen_insn_execbuf, sizeof (insns));
					insns[KPROBES_TRAMP_INSN_IDX] = insn[0];
				}			
				//insns[KPROBES_TRAMP_RET_BREAK_IDX] = UNDEF_INSTRUCTION;
				insns[7] = (kprobe_opcode_t) (p->addr + 1);
				DBPRINTF ("arch_prepare_kprobe: insn %lx", insn[0]);
				DBPRINTF ("arch_prepare_kprobe: to %p - %lx %lx %lx %lx %lx %lx %lx %lx %lx", 
						p->ainsn.insn, insns[0], insns[1], insns[2], insns[3], insns[4], 
						insns[5], insns[6], insns[7], insns[8]);
				memcpy (p->ainsn.insn, insns, sizeof(insns));
			}
#elif defined(CONFIG_MIPS)
			p->ainsn.boostable = 0;
			memcpy (insns, gen_insn_execbuf, sizeof (insns));
			insns[KPROBES_TRAMP_INSN_IDX] = insn[0];
			insns[KPROBES_TRAMP_SS_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
			insns[KPROBES_TRAMP_RET_BREAK_IDX] = UNDEF_INSTRUCTION;
			DBPRINTF ("arch_prepare_kprobe: insn %lx", insn[0]);
			DBPRINTF ("arch_prepare_kprobe: to %p - %lx %lx %lx", 
					p->ainsn.insn, insns[0], insns[1], insns[2]);
			memcpy (p->ainsn.insn, insns, sizeof(insns));
#elif defined(CONFIG_X86)
			if (can_boost (p->addr))
				p->ainsn.boostable = 0;
			else
				p->ainsn.boostable = -1;
			memcpy (p->ainsn.insn, insn, MAX_INSN_SIZE * sizeof (kprobe_opcode_t));
#endif
		}
		else
		{
			free_insn_slot (&kprobe_insn_pages, NULL, p->ainsn.insn, 0);
		}
	}

	return ret;
}

int
arch_prepare_kretprobe (struct kretprobe *p)
{
	int ret = 0;
#if 0
	if ((unsigned long) p->kp.addr & 0x01)
	{
		DBPRINTF ("Attempt to register kprobe at an unaligned address\n");
		ret = -EINVAL;
	}

	/* XXX: Might be a good idea to check if p->addr is a valid
	 * kernel address as well... */

	if (!ret)
	{
		kprobe_opcode_t insn;
		struct arch_specific_insn ainsn;
		memcpy (&insn, p->kp.addr, MAX_INSN_SIZE * sizeof (kprobe_opcode_t));
		ainsn.insn = &insn;
		ret = arch_check_insn (&ainsn);
		if (!ret)
		{
			p->kp.opcode = *p->kp.addr;
#if defined(CONFIG_X86)
			memcpy (p->kp.ainsn.insn, p->kp.addr, MAX_INSN_SIZE * sizeof (kprobe_opcode_t));
#endif
		}
	}
#endif
	return ret;
}

int
arch_prepare_uprobe (struct kprobe *p, struct task_struct *task, int atomic)
{
	int ret = 0;
	kprobe_opcode_t insns[UPROBES_TRAMP_LEN];
#if defined(CONFIG_ARM)
	int uregs, pc_dep;
#endif

#if !defined(CONFIG_X86)
	if ((unsigned long) p->addr & 0x01)
	{
		DBPRINTF ("Attempt to register kprobe at an unaligned address");
		ret = -EINVAL;
	}
#endif

	if (!ret)
	{
		kprobe_opcode_t insn[MAX_INSN_SIZE];
		struct arch_specific_insn ainsn;
		
		if (!read_proc_vm_atomic (task, (unsigned long) p->addr, &insn, MAX_INSN_SIZE * sizeof(kprobe_opcode_t)))
			panic ("failed to read memory %p!\n", p->addr);
		ainsn.insn = insn;
		ret = arch_check_insn (&ainsn);
		if (!ret)
		{
			p->opcode = insn[0];
			p->ainsn.insn = get_insn_slot(task, atomic);
			if (!p->ainsn.insn)
				return -ENOMEM;
#if defined(CONFIG_ARM)
			p->ainsn.boostable = 1;
			uregs = pc_dep = 0;
			// Rn, Rm ,Rd
			if (ARM_INSN_MATCH (DPIS, insn[0]) || ARM_INSN_MATCH (LRO, insn[0]) || 
				ARM_INSN_MATCH (SRO, insn[0]))
			{

				uregs = 0xb;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_REG_RM (insn[0]) == 15) || 
					(ARM_INSN_MATCH (SRO, insn[0]) && (ARM_INSN_REG_RD (insn[0]) == 15)))
				{

					DBPRINTF ("Unboostable insn %lx, DPIS/LRO/SRO\n", insn[0]);
					pc_dep = 1;
				}
			}
			// Rn ,Rd
			else if (ARM_INSN_MATCH (DPI, insn[0]) || ARM_INSN_MATCH (LIO, insn[0]) || 
					 ARM_INSN_MATCH (SIO, insn[0]))
			{

				uregs = 0x3;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_MATCH (SIO, insn[0]) && 
					(ARM_INSN_REG_RD (insn[0]) == 15)))
				{

					pc_dep = 1;
					DBPRINTF ("Unboostable insn %lx/%p/%d, DPI/LIO/SIO\n", insn[0], p, p->ainsn.boostable);
				}
			}
			// Rn, Rm, Rs                                   
			else if (ARM_INSN_MATCH (DPRS, insn[0]))
			{

				uregs = 0xd;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_REG_RM (insn[0]) == 15) || 
					(ARM_INSN_REG_RS (insn[0]) == 15))
				{

					pc_dep = 1;
					DBPRINTF ("Unboostable insn %lx, DPRS\n", insn[0]);
				}
			}
			// register list
			else if (ARM_INSN_MATCH (SM, insn[0]))
			{

				uregs = 0x10;
				if (ARM_INSN_REG_MR (insn[0], 15))
				{

					DBPRINTF ("Unboostable insn %lx, SM\n", insn[0]);
					pc_dep = 1;
				}
			}
			// check instructions that can write result to SP andu uses PC
			if (pc_dep  && (ARM_INSN_REG_RD (ainsn.insn[0]) == 13))
			{
				static int count;
				count++;
				//printk ("insn writes result to SP and uses PC: %lx/%d\n", ainsn.insn[0], count);
				free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn, 0);
				ret = -EFAULT;
			}
			else {
				if (uregs && pc_dep)
				{
					memcpy (insns, pc_dep_insn_execbuf, sizeof (insns));
					if (prep_pc_dep_insn_execbuf (insns, insn[0], uregs) != 0)
					{
						DBPRINTF ("failed to prepare exec buffer for insn %lx!", insn[0]);
						free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn, 0);
						return -EINVAL;
					}
					//insns[UPROBES_TRAMP_SS_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
					insns[6] = (kprobe_opcode_t) (p->addr + 2);
				}
				else
				{
					memcpy (insns, gen_insn_execbuf, sizeof (insns));
					insns[UPROBES_TRAMP_INSN_IDX] = insn[0];
				}			
				insns[UPROBES_TRAMP_RET_BREAK_IDX] = UNDEF_INSTRUCTION;
				insns[7] = (kprobe_opcode_t) (p->addr + 1);
				DBPRINTF ("arch_prepare_uprobe: to %p - %lx %lx %lx %lx %lx %lx %lx %lx %lx", 
						p->ainsn.insn, insns[0], insns[1], insns[2], insns[3], insns[4], 
						insns[5], insns[6], insns[7], insns[8]);
			}
#elif defined(CONFIG_MIPS)
			p->ainsn.boostable = 0;
			memcpy (insns, gen_insn_execbuf, sizeof (insns));
			insns[UPROBES_TRAMP_INSN_IDX] = insn[0];
			insns[UPROBES_TRAMP_SS_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
			insns[UPROBES_TRAMP_RET_BREAK_IDX] = UNDEF_INSTRUCTION;
			DBPRINTF ("arch_prepare_uprobe: insn %lx", insn[0]);
			DBPRINTF ("arch_prepare_uprobe: to %p - %lx %lx %lx", 
					p->ainsn.insn, insns[0], insns[1], insns[2]);
#elif defined(CONFIG_X86)
			if (can_boost (insn))
				p->ainsn.boostable = 0;
			else
				p->ainsn.boostable = -1;
			memcpy (&insns[UPROBES_TRAMP_INSN_IDX], insn, MAX_INSN_SIZE*sizeof(kprobe_opcode_t));
			insns[UPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
			/*printk ("arch_prepare_uprobe: to %p - %02x %02x %02x %02x %02x %02x %02x %02x "
												   "%02x %02x %02x %02x %02x %02x %02x %02x %02x", p->ainsn.insn 
												, insns[0], insns[1], insns[2], insns[3]
												, insns[4], insns[5], insns[6], insns[7]
												, insns[8], insns[9], insns[10], insns[11]
												, insns[12], insns[13], insns[14], insns[15], insns[16]);*/
#endif
			if (!write_proc_vm_atomic (task, (unsigned long) p->ainsn.insn, insns, sizeof (insns)))
			{
				panic("failed to write memory %p!\n", p->ainsn.insn);
				DBPRINTF ("failed to write insn slot to process memory: insn %p, addr %p, probe %p!", insn, p->ainsn.insn, p->addr);
				/*printk ("failed to write insn slot to process memory: %p/%d insn %lx, addr %p, probe %p!\n", 
						task, task->pid, insn, p->ainsn.insn, p->addr);*/
				free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn, 0);
				return -EINVAL;
			}
			/*if(!read_proc_vm_atomic(task, (unsigned long)p->ainsn.insn, insns, 3*MAX_INSN_SIZE*sizeof(kprobe_opcode_t)))
			   panic("failed to read memory %p!\n", p->addr);
			   printk("arch_prepare_uprobe: from %p - %lx %lx %lx\n", p->ainsn.insn, insns[0], insns[1], insns[2]); */
		}
	}

	return ret;
}

int
arch_prepare_uretprobe (struct kretprobe *p, struct task_struct *task)//, struct vm_area_struct **vma, struct page **page, unsigned long **kaddr)
{
	int ret = 0;
#if 0
	if ((unsigned long) p->kp.addr & 0x01)
	{
		DBPRINTF ("Attempt to register kprobe at an unaligned address\n");
		ret = -EINVAL;
	}
#if defined(CONFIG_X86)
#warning arch_prepare_uretprobe is not implemented for this arch!!!
#endif
#endif
	return ret;
}

void
arch_remove_kprobe (struct kprobe *p, struct task_struct *task)
{
	//mutex_lock(&kprobe_mutex);
	if(p->tgid)
		free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn, (p->ainsn.boostable == 1));
	else
		free_insn_slot (&kprobe_insn_pages, NULL, p->ainsn.insn, (p->ainsn.boostable == 1));
	//mutex_unlock(&kprobe_mutex)
}

static unsigned long alloc_user_pages(struct task_struct *task, unsigned long len, 
									 unsigned long prot, unsigned long flags, int atomic)
{
#if 1
	long ret = 0;
	struct task_struct *otask = current;
	struct mm_struct *mm;
	
	mm = atomic ? task->active_mm : get_task_mm (task);
	if (mm){
		if(!atomic)
			down_write (&mm->mmap_sem);
		// FIXME: its seems to be bad decision to replace 'current' pointer temporarily 
		current_thread_info()->task = task;
		ret = (unsigned long)do_mmap_pgoff(0, 0, len, prot, flags, 0);
		current_thread_info()->task = otask;
		//printk ("mmap proc %p/%d %p/%d (%ld/%lx)\n", task, task->pid, current, current->pid, ret, ret);
		if(!atomic){
			up_write (&mm->mmap_sem);
			mmput(mm);
		}
		/*if(ret < 0){
			printk ("failed to mmap page in proc %d (%ld)", task->pid, ret);
			ret = 0;
		}*/
	}
	else
		printk ("proc %d has no mm", task->pid);
	return (unsigned long)ret;
#else
	struct file * file = 0;
	unsigned long addr = 0, pgoff = 0;	
	struct mm_struct * mm = task->mm;
	struct vm_area_struct * vma, * prev;
	struct inode *inode;
	unsigned int vm_flags;
	int correct_wcount = 0;
	int error;
	struct rb_node ** rb_link, * rb_parent;
	int accountable = 1;
	unsigned long charged = 0, reqprot = prot;

    if (file) {
        if (is_file_hugepages(file))
            accountable = 0;

        if (!file->f_op || !file->f_op->mmap)
            return -ENODEV;

        if ((prot & PROT_EXEC) &&
            (file->f_vfsmnt->mnt_flags & MNT_NOEXEC))
            return -EPERM;
    }
    /*
     * Does the application expect PROT_READ to imply PROT_EXEC?
     *
     * (the exception is when the underlying filesystem is noexec
     *  mounted, in which case we dont add PROT_EXEC.)
     */
    if ((prot & PROT_READ) && (task->personality & READ_IMPLIES_EXEC))
        if (!(file && (file->f_vfsmnt->mnt_flags & MNT_NOEXEC)))
            prot |= PROT_EXEC;

    if (!len)
        return -EINVAL;

    /* Careful about overflows.. */
    len = PAGE_ALIGN(len);
    if (!len || len > TASK_SIZE)
        return -ENOMEM;

    /* offset overflow? */
    if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
       return -EOVERFLOW;

    /* Too many mappings? */
    if (mm->map_count > sysctl_max_map_count)
        return -ENOMEM;

    /* Obtain the address to map to. we verify (or select) it and ensure
     * that it represents a valid section of the address space.
     */
    addr = get_unmapped_area(file, addr, len, pgoff, flags);
    if (addr & ~PAGE_MASK)
        return addr;

    /* Do simple checking here so the lower-level routines won't have
     * to. we assume access permissions have been handled by the open
     * of the memory object, so we don't do any here.
     */
    vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
                mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

    if (flags & MAP_LOCKED) {
        if (!can_do_mlock())
            return -EPERM;
        vm_flags |= VM_LOCKED;
    }
    /* mlock MCL_FUTURE? */
    if (vm_flags & VM_LOCKED) {
        unsigned long locked, lock_limit;
        locked = len >> PAGE_SHIFT;
        locked += mm->locked_vm;
        lock_limit = task->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
        lock_limit >>= PAGE_SHIFT;
        if (locked > lock_limit && !capable(CAP_IPC_LOCK))
            return -EAGAIN;
    }

    inode = file ? file->f_dentry->d_inode : NULL;

    if (file) {
        switch (flags & MAP_TYPE) {
        case MAP_SHARED:
            if ((prot&PROT_WRITE) && !(file->f_mode&FMODE_WRITE))
                return -EACCES;

            /*
             * Make sure we don't allow writing to an append-only
             * file..
             */
            if (IS_APPEND(inode) && (file->f_mode & FMODE_WRITE))
                return -EACCES;

            /*
             * Make sure there are no mandatory locks on the file.
             */
            if (locks_verify_locked(inode))
                return -EAGAIN;

            vm_flags |= VM_SHARED | VM_MAYSHARE;
            if (!(file->f_mode & FMODE_WRITE))
                vm_flags &= ~(VM_MAYWRITE | VM_SHARED);

            /* fall through */
        case MAP_PRIVATE:
            if (!(file->f_mode & FMODE_READ))
                return -EACCES;
            break;

        default:
            return -EINVAL;
        }
    } else {
        switch (flags & MAP_TYPE) {
        case MAP_SHARED:
            vm_flags |= VM_SHARED | VM_MAYSHARE;
            break;
        case MAP_PRIVATE:
            /*
             * Set pgoff according to addr for anon_vma.
             */
            pgoff = addr >> PAGE_SHIFT;
            break;
        default:
            return -EINVAL;
        }
    }


    error = security_file_mmap(file, reqprot, prot, flags);
    if (error)
        return error;
            
    /* Clear old maps */
    error = -ENOMEM;
munmap_back:
        vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
        if (vma && vma->vm_start < addr + len) {
            if (do_munmap(mm, addr, len))
                return -ENOMEM;
            goto munmap_back;
        }

        /* Check against address space limit. */
        if (!may_expand_vm(mm, len >> PAGE_SHIFT))
            return -ENOMEM;

        if (accountable && (!(flags & MAP_NORESERVE) ||
                        sysctl_overcommit_memory == OVERCOMMIT_NEVER)) {
            if (vm_flags & VM_SHARED) {
                /* Check memory availability in shmem_file_setup? */
                vm_flags |= VM_ACCOUNT;
            } else if (vm_flags & VM_WRITE) {
                /*
                 * Private writable mapping: check memory availability
                 */
                charged = len >> PAGE_SHIFT;
                if (security_vm_enough_memory(charged))
                    return -ENOMEM;
                vm_flags |= VM_ACCOUNT;
            }
        }

        /*
         * Can we just expand an old private anonymous mapping?
         * The VM_SHARED test is necessary because shmem_zero_setup
         * will create the file object for a shared anonymous map below.
         */
        if (!file && !(vm_flags & VM_SHARED) &&
            vma_merge(mm, prev, addr, addr + len, vm_flags,
                                    NULL, NULL, pgoff, NULL))
            goto out;

        /*
         * Determine the object being mapped and call the appropriate
         * specific mapper. the address has already been validated, but
         * not unmapped, but the maps are removed from the list.
         */
        vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
        if (!vma) {
            error = -ENOMEM;
            goto unacct_error;
        }
        memset(vma, 0, sizeof(*vma));

        vma->vm_mm = mm;
        vma->vm_start = addr;
        vma->vm_end = addr + len;
        vma->vm_flags = vm_flags;
        vma->vm_page_prot = protection_map[vm_flags & 0x0f];
        vma->vm_pgoff = pgoff;

        if (file) {
            error = -EINVAL;
            if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
                goto free_vma;
            if (vm_flags & VM_DENYWRITE) {
                error = deny_write_access(file);
                if (error)
                        goto free_vma;
                correct_wcount = 1;
            }
            vma->vm_file = file;
            get_file(file);
            error = file->f_op->mmap(file, vma);
            if (error)
                goto unmap_and_free_vma;
        } else if (vm_flags & VM_SHARED) {
            error = shmem_zero_setup(vma);
            if (error)
                goto free_vma;
        }

        /* We set VM_ACCOUNT in a shared mapping's vm_flags, to inform
         * shmem_zero_setup (perhaps called through /dev/zero's ->mmap)
         * that memory reservation must be checked; but that reservation
         * belongs to shared memory object, not to vma: so now clear it.
         */
        if ((vm_flags & (VM_SHARED|VM_ACCOUNT)) == (VM_SHARED|VM_ACCOUNT))
            vma->vm_flags &= ~VM_ACCOUNT;

        /* Can addr have changed??
         *
         * Answer: Yes, several device drivers can do it in their
         *         f_op->mmap method. -DaveM
         */
        addr = vma->vm_start;
        pgoff = vma->vm_pgoff;
        vm_flags = vma->vm_flags;

        if (!file || !vma_merge(mm, prev, addr, vma->vm_end,
                    vma->vm_flags, NULL, file, pgoff, vma_policy(vma))) {
            file = vma->vm_file;
            vma_link(mm, vma, prev, rb_link, rb_parent);
            if (correct_wcount)
                atomic_inc(&inode->i_writecount);
        } else {
            if (file) {
                if (correct_wcount)
                    atomic_inc(&inode->i_writecount);
                fput(file);
            }
            mpol_free(vma_policy(vma));
            kmem_cache_free(vm_area_cachep, vma);
        }
out:    
        mm->total_vm += len >> PAGE_SHIFT;
        vm_stat_account(mm, vm_flags, file, len >> PAGE_SHIFT);
        if (vm_flags & VM_LOCKED) {
            mm->locked_vm += len >> PAGE_SHIFT;
            make_pages_present(addr, addr + len);
        }
        if (flags & MAP_POPULATE) {
            up_write(&mm->mmap_sem);
            sys_remap_file_pages(addr, len, 0,
                                    pgoff, flags & MAP_NONBLOCK);
            down_write(&mm->mmap_sem);
        }
        return addr;

unmap_and_free_vma:
        if (correct_wcount)
            atomic_inc(&inode->i_writecount);
        vma->vm_file = NULL;
        fput(file);

        /* Undo any partial mapping done by a device driver. */
        unmap_region(mm, vma, prev, vma->vm_start, vma->vm_end);
        charged = 0;
free_vma:
        kmem_cache_free(vm_area_cachep, vma);
unacct_error:
        if (charged)
            vm_unacct_memory(charged);
        return error;
#endif
}

static int __kprobes
check_safety (void)
{
	int ret = 0;	
#if defined(CONFIG_PREEMPT) && defined(CONFIG_PM)
	ret = freeze_processes ();
	if (ret == 0)
	{
		struct task_struct *p, *q;
		do_each_thread (p, q)
		{
			if (p != current && p->state == TASK_RUNNING && p->pid != 0)
			{
				printk ("Check failed: %s is running\n", p->comm);
				ret = -1;
				goto loop_end;
			}
		}
		while_each_thread (p, q);
	}
loop_end:
	thaw_processes ();
#else
	synchronize_sched ();
#endif
	return ret;
}

/**
 * get_us_insn_slot() - Find a slot on an executable page for an instruction.
 * We allocate an executable page if there's no room on existing ones.
 */
kprobe_opcode_t __kprobes *
get_insn_slot (struct task_struct *task, int atomic)
{
	struct kprobe_insn_page *kip;
	struct hlist_node *pos;
	struct hlist_head *page_list = task ? &uprobe_insn_pages : &kprobe_insn_pages;
	unsigned slots_per_page = INSNS_PER_PAGE, slot_size = MAX_INSN_SIZE;

	if(task) {
		slots_per_page = INSNS_PER_PAGE/UPROBES_TRAMP_LEN;
		slot_size = UPROBES_TRAMP_LEN;
	}
	else {
		slots_per_page = INSNS_PER_PAGE/KPROBES_TRAMP_LEN;
		slot_size = KPROBES_TRAMP_LEN;		
	}
	
retry:
	hlist_for_each_entry (kip, pos, page_list, hlist)
	{
		if (kip->nused < slots_per_page)
		{
			int i;
			for (i = 0; i < slots_per_page; i++)
			{
				if (kip->slot_used[i] == SLOT_CLEAN)
				{
					if(!task || (kip->tgid == task->tgid)){
						kip->slot_used[i] = SLOT_USED;
						kip->nused++;
						return kip->insns + (i * slot_size);
					}
				}
			}
			/* Surprise!  No unused slots.  Fix kip->nused. */
			kip->nused = slots_per_page;
		}
	}

	/* If there are any garbage slots, collect it and try again. */
	if(task) {
		if (uprobe_garbage_slots && collect_garbage_slots(page_list, task) == 0)
			goto retry;
	}
	else {
		if (kprobe_garbage_slots && collect_garbage_slots(page_list, task) == 0)
			goto retry;		
	}

	/* All out of space.  Need to allocate a new page. Use slot 0. */
	kip = kmalloc(sizeof(struct kprobe_insn_page), GFP_KERNEL);
	if (!kip)
		return NULL;

	kip->slot_used = kmalloc(sizeof(char)*slots_per_page, GFP_KERNEL);
	if (!kip->slot_used){
		kfree(kip);
		return NULL;
	}

	if(task) {
		kip->insns = (kprobe_opcode_t *)alloc_user_pages(task, PAGE_SIZE, 
						PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, atomic);
	}
	else {
#if defined(CONFIG_X86)
		kip->insns = module_alloc (PAGE_SIZE);
#else
		kip->insns = kmalloc(PAGE_SIZE, GFP_KERNEL);
#endif
	}
	if (!kip->insns)
	{
		kfree (kip->slot_used);
		kfree (kip);
		return NULL;
	}	
	INIT_HLIST_NODE (&kip->hlist);
	hlist_add_head (&kip->hlist, page_list);
	memset(kip->slot_used, SLOT_CLEAN, slots_per_page);
	kip->slot_used[0] = SLOT_USED;
	kip->nused = 1;
	kip->ngarbage = 0;
	kip->tgid = task ? task->tgid : 0;
	return kip->insns;
}

/* Return 1 if all garbages are collected, otherwise 0. */
static int __kprobes
collect_one_slot (struct hlist_head *page_list, struct task_struct *task, 
					struct kprobe_insn_page *kip, int idx)
{
	struct mm_struct *mm;

	kip->slot_used[idx] = SLOT_CLEAN;
	kip->nused--;
	DBPRINTF("collect_one_slot: nused=%d", kip->nused);
	if (kip->nused == 0)
	{
		/*
		 * Page is no longer in use.  Free it unless
		 * it's the last one.  We keep the last one
		 * so as not to have to set it up again the
		 * next time somebody inserts a probe.
		 */
		hlist_del (&kip->hlist);
		if (!task && hlist_empty (page_list))
		{
			INIT_HLIST_NODE (&kip->hlist);
			hlist_add_head (&kip->hlist, page_list);
		}
		else
		{
			if(task){
//E. G.: This code provides kernel dump because of rescheduling while atomic. 
//As workaround, this code was commented. In this case we will have memory leaks 
//for instrumented process, but instrumentation process should functionate correctly. 
//Planned that good solution for this problem will be done during redesigning KProbe 
//for improving supportability and performance.
#if 0
				//printk("collect_one_slot %p/%d\n", task, task->pid);
				mm = get_task_mm (task);
				if (mm){			
					down_write (&mm->mmap_sem);
					do_munmap(mm, (unsigned long)(kip->insns), PAGE_SIZE);
					up_write (&mm->mmap_sem);
					mmput(mm);
				}
#endif
				kip->insns = NULL; //workaround
				kip->tgid = 0;
			}
			else {
#if defined(CONFIG_X86)			
				module_free (NULL, kip->insns);
#else
				vfree(kip->insns);
#endif
			}
			kfree (kip->slot_used);
			kfree (kip);
		}
		return 1;
	}
	return 0;
}

static int __kprobes
collect_garbage_slots (struct hlist_head *page_list, struct task_struct *task)
{
	struct kprobe_insn_page *kip;
	struct hlist_node *pos, *next;
	unsigned slots_per_page = INSNS_PER_PAGE;

	/* Ensure no-one is preepmted on the garbages */
	if (!task && check_safety() != 0)
		return -EAGAIN;

	if(task)
		slots_per_page = INSNS_PER_PAGE/UPROBES_TRAMP_LEN;
	else
		slots_per_page = INSNS_PER_PAGE/KPROBES_TRAMP_LEN;
	
	hlist_for_each_entry_safe (kip, pos, next, page_list, hlist)
	{
		int i;
		if ((task && (kip->tgid != task->tgid)) || (kip->ngarbage == 0))
			continue;
		kip->ngarbage = 0;	/* we will collect all garbages */
		for (i = 0; i < slots_per_page; i++)
		{
			if (kip->slot_used[i] == SLOT_DIRTY && collect_one_slot (page_list, task, kip, i))
				break;
		}
	}
	if(task)	uprobe_garbage_slots = 0;
	else		kprobe_garbage_slots = 0;
	return 0;
}

void purge_garbage_uslots(struct task_struct *task, int atomic)
{
	if(collect_garbage_slots(&uprobe_insn_pages, task))
		panic("failed to collect garbage slotsfo for task %s/%d/%d", task->comm, task->tgid, task->pid);
}

void __kprobes
free_insn_slot (struct hlist_head *page_list, struct task_struct *task, kprobe_opcode_t *slot, int dirty)
{
	struct kprobe_insn_page *kip;
	struct hlist_node *pos;
	unsigned slots_per_page = INSNS_PER_PAGE, slot_size = MAX_INSN_SIZE;

	if(task) {	
		slots_per_page = INSNS_PER_PAGE/UPROBES_TRAMP_LEN;
		slot_size = UPROBES_TRAMP_LEN;
	}
	else {
		slots_per_page = INSNS_PER_PAGE/KPROBES_TRAMP_LEN;
		slot_size = KPROBES_TRAMP_LEN;
	}
	
	DBPRINTF("free_insn_slot: dirty %d, %p/%d", dirty, task, task?task->pid:0);
	hlist_for_each_entry (kip, pos, page_list, hlist)
	{
		DBPRINTF("free_insn_slot: kip->insns=%p slot=%p", kip->insns, slot);
		if ((kip->insns <= slot) && (slot < kip->insns + (INSNS_PER_PAGE * MAX_INSN_SIZE)))
		{
			int i = (slot - kip->insns) / slot_size;
			if (dirty)
			{
				kip->slot_used[i] = SLOT_DIRTY;
				kip->ngarbage++;
			}
			else
			{
				collect_one_slot (page_list, task, kip, i);
			}
			break;
		}
	}

	if (dirty){
		if(task){
			if(++uprobe_garbage_slots > slots_per_page)
				collect_garbage_slots (page_list, task);
		}
		else if(++kprobe_garbage_slots > slots_per_page)
			collect_garbage_slots (page_list, task);
	}
}

static void
prepare_singlestep (struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_X86)
	if(p->ss_addr)
	{
		regs->EREG (ip) = (unsigned long)p->ss_addr;
		p->ss_addr = NULL;
	}
	else
	{
		regs->EREG (flags) |= TF_MASK;
		regs->EREG (flags) &= ~IF_MASK;
		/*single step inline if the instruction is an int3 */
		if (p->opcode == BREAKPOINT_INSTRUCTION){
			regs->EREG (ip) = (unsigned long) p->addr;
			//printk("break_insn!!!\n");
		}
		else
			regs->EREG (ip) = (unsigned long) p->ainsn.insn;
	}
	//printk("singlestep %p/%lx\n", p->addr, p->ainsn.insn);
#elif defined(CONFIG_ARM)
	if(p->ss_addr)
	{
		regs->uregs[15] = (unsigned long) p->ss_addr;
		p->ss_addr = NULL;
	}
	else
		regs->uregs[15] = (unsigned long) p->ainsn.insn;
	//DBPRINTF("prepare_singlestep: %p/%p/%d\n", p, p->addr, p->ainsn.boostable);
#elif defined(CONFIG_MIPS)
	if(p->ss_addr)
	{
		regs->cp0_epc = (unsigned long) p->ss_addr;
		p->ss_addr = NULL;
	}
	else
		regs->cp0_epc = (unsigned long) p->ainsn.insn;
#endif
	//if(p->tgid)
		//printk("prepare_singlestep: %p/%d to %lx\n", p->addr, p->ainsn.boostable, regs->EREG (ip));
	//printk("SS[%lx] to %lx/%lx/%lx\n", p->addr, regs->uregs[15], p->ss_addr, p);
}

static void __kprobes
save_previous_kprobe (struct kprobe_ctlblk *kcb, struct kprobe *cur_p)
{
	if (kcb->prev_kprobe.kp != NULL)
	{
		panic ("no space to save new probe[%lu]: task = %d/%s, prev %d/%p, current %d/%p, new %d/%p,",
				nCount, current->pid, current->comm, kcb->prev_kprobe.kp->tgid, kcb->prev_kprobe.kp->addr, 
				kprobe_running()->tgid, kprobe_running()->addr, cur_p->tgid, cur_p->addr);
	}
#if defined(CONFIG_X86)
	kcb->prev_kprobe.old_eflags = kcb->kprobe_old_eflags;
	kcb->prev_kprobe.saved_eflags = kcb->kprobe_saved_eflags;
#endif
	kcb->prev_kprobe.kp = kprobe_running ();
	kcb->prev_kprobe.status = kcb->kprobe_status;
}

static void __kprobes
restore_previous_kprobe (struct kprobe_ctlblk *kcb)
{
	__get_cpu_var (current_kprobe) = kcb->prev_kprobe.kp;
	kcb->kprobe_status = kcb->prev_kprobe.status;
	kcb->prev_kprobe.kp = NULL;
	kcb->prev_kprobe.status = 0;
#if defined(CONFIG_X86)
	kcb->kprobe_old_eflags = kcb->prev_kprobe.old_eflags;
	kcb->kprobe_saved_eflags = kcb->prev_kprobe.saved_eflags;
#endif
}

static void __kprobes
set_current_kprobe (struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb)
{
	__get_cpu_var (current_kprobe) = p;
	DBPRINTF ("set_current_kprobe[%lu]: p=%p addr=%p\n", nCount, p, p->addr);
#if defined(CONFIG_X86)
	kcb->kprobe_saved_eflags = kcb->kprobe_old_eflags = (regs->EREG (flags) & (TF_MASK | IF_MASK));
	if (is_IF_modifier (p->opcode))
		kcb->kprobe_saved_eflags &= ~IF_MASK;
#endif
}

#define REENTER

#ifdef _DEBUG
int gSilent = 1;
#endif

#if defined(CONFIG_X86)
int
kprobe_handler (struct pt_regs *regs)
{
	struct kprobe *p = 0;
	int ret = 0, pid = 0, retprobe = 0, reenter = 0;
	kprobe_opcode_t *addr = NULL;
	struct kprobe_ctlblk *kcb;	
	
	nCount++;

	/* We're in an interrupt, but this is clear and BUG()-safe. */
#ifdef _DEBUG
	gSilent = 1;
#endif

	addr = (kprobe_opcode_t *) (regs->EREG (ip) - sizeof (kprobe_opcode_t));
	DBPRINTF ("KPROBE[%lu]: regs->eip = 0x%lx addr = 0x%p\n", nCount, regs->EREG (ip), addr);
	
	preempt_disable ();
	
	kcb = get_kprobe_ctlblk ();

	if (user_mode_vm(regs))
	{
#ifdef _DEBUG
		gSilent = 0;
#endif
		//printk("exception[%lu] from user mode %s/%u/%u addr %p.\n", nCount, current->comm, current->pid, current->tgid, addr);
		pid = current->tgid;
	}
	
	/* Check we're not actually recursing */
	if (kprobe_running ())
	{
		DBPRINTF ("lock???");
		p = get_kprobe (addr, pid, current);
		if (p)
		{
			DBPRINTF ("reenter p = %p", p);
			if(!pid){
				if (kcb->kprobe_status == KPROBE_HIT_SS && *p->ainsn.insn == BREAKPOINT_INSTRUCTION)
				{
					regs->EREG (flags) &= ~TF_MASK;
					regs->EREG (flags) |= kcb->kprobe_saved_eflags;
					goto no_kprobe;
				}
			}
			else {
				//#warning BREAKPOINT_INSTRUCTION user mode handling is missed!!! 
			}
				
			/* We have reentered the kprobe_handler(), since
			 * another probe was hit while within the handler.
			 * We here save the original kprobes variables and
			 * just single step on the instruction of the new probe
			 * without calling any user handlers.
			 */
			save_previous_kprobe (kcb, p);
			set_current_kprobe (p, regs, kcb);
			kprobes_inc_nmissed_count (p);
			prepare_singlestep (p, regs);
			kcb->kprobe_status = KPROBE_REENTER;
#ifdef _DEBUG
			gSilent = 1;
#endif
			return 1;
		}
		else
		{
			if(!pid){
				if (*addr != BREAKPOINT_INSTRUCTION)
				{
					/* The breakpoint instruction was removed by
					 * another cpu right after we hit, no further
					 * handling of this interrupt is appropriate
					 */
					regs->EREG (ip) -= sizeof (kprobe_opcode_t);
					ret = 1;
					goto no_kprobe;
				}
			}
			else {
				//#warning BREAKPOINT_INSTRUCTION user mode handling is missed!!! 
				//we can reenter probe upon uretprobe exception   
				DBPRINTF ("check for UNDEF_INSTRUCTION %p\n", addr);
				// UNDEF_INSTRUCTION from user space
				p = get_kprobe_by_insn_slot (addr-UPROBES_TRAMP_RET_BREAK_IDX, pid, current);
				if (p) {
					save_previous_kprobe (kcb, p);
					kcb->kprobe_status = KPROBE_REENTER;
					reenter = 1;
					retprobe = 1;
					DBPRINTF ("uretprobe %p\n", addr);
				}
			}
			if(!p){
				p = __get_cpu_var (current_kprobe);
				if(p->tgid)
					panic("after uhandler");
				DBPRINTF ("kprobe_running !!! p = 0x%p p->break_handler = 0x%p", p, p->break_handler);
				if (p->break_handler && p->break_handler (p, regs))
				{
					DBPRINTF ("kprobe_running !!! goto ss");
					goto ss_probe;
				}
				DBPRINTF ("kprobe_running !!! goto no");
				DBPRINTF ("no_kprobe");
				goto no_kprobe;
			}
		}
	}

	DBPRINTF ("get_kprobe %p", addr);
	if (!p)
		p = get_kprobe (addr, pid, current);
	if (!p)
	{
		if(!pid){
			if (*addr != BREAKPOINT_INSTRUCTION)
			{
				/*
				 * The breakpoint instruction was removed right
				 * after we hit it.  Another cpu has removed
				 * either a probepoint or a debugger breakpoint
				 * at this address.  In either case, no further
				 * handling of this interrupt is appropriate.
				 * Back up over the (now missing) int3 and run
				 * the original instruction.
				 */
				regs->EREG (ip) -= sizeof (kprobe_opcode_t);
				ret = 1;
			}
		}
		else {
			//#warning BREAKPOINT_INSTRUCTION user mode handling is missed!!! 
			DBPRINTF ("search UNDEF_INSTRUCTION %p\n", addr);
			// UNDEF_INSTRUCTION from user space
			p = get_kprobe_by_insn_slot (addr-UPROBES_TRAMP_RET_BREAK_IDX, pid, current);
			if (!p) {
				// Not one of ours: let kernel handle it
				DBPRINTF ("no_kprobe");
				//printk("no_kprobe2 ret = %d\n", ret);
				goto no_kprobe;
			}
			retprobe = 1;
			DBPRINTF ("uretprobe %p\n", addr);
		}
		if(!p) {
			/* Not one of ours: let kernel handle it */
			DBPRINTF ("no_kprobe");
			goto no_kprobe;
		}
	}
	set_current_kprobe (p, regs, kcb);
	if(!reenter)
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;

	if (retprobe)		//(einsn == UNDEF_INSTRUCTION)
		ret = trampoline_probe_handler (p, regs);
	else if (p->pre_handler)
		ret = p->pre_handler (p, regs);

	if (ret)
	{
		if (ret == 2) { // we have alreadyc called the handler, so just single step the instruction
			DBPRINTF ("p->pre_handler[%lu] 2", nCount);
			goto ss_probe;
		}
		DBPRINTF ("p->pre_handler[%lu] 1", nCount);
		/* handler has already set things up, so skip ss setup */
#ifdef _DEBUG
		gSilent = 1;
#endif
		return 1;
	}
	DBPRINTF ("p->pre_handler[%lu] 0", nCount);

ss_probe:
	DBPRINTF ("p = %p\n", p);
	DBPRINTF ("p->opcode = 0x%lx *p->addr = 0x%lx p->addr = 0x%p\n", (unsigned long) p->opcode, p->tgid ? 0 : (unsigned long) (*p->addr), p->addr);

#if !defined(CONFIG_PREEMPT) || defined(CONFIG_PM)
	if (p->ainsn.boostable == 1 && !p->post_handler)
	{
		/* Boost up -- we can execute copied instructions directly */
		reset_current_kprobe ();
		regs->EREG (ip) = (unsigned long) p->ainsn.insn;
		preempt_enable_no_resched ();
#ifdef _DEBUG
		gSilent = 1;
#endif
		return 1;
	}
#endif // !CONFIG_PREEMPT
	prepare_singlestep (p, regs);
	kcb->kprobe_status = KPROBE_HIT_SS;
#ifdef _DEBUG
	gSilent = 1;
#endif
	return 1;

no_kprobe:

	preempt_enable_no_resched ();
#ifdef _DEBUG
	gSilent = 1;
#endif
	return ret;
}

#else
int
kprobe_handler (struct pt_regs *regs)
{
	struct kprobe *p = 0;
	int ret = 0, pid = 0, retprobe = 0, reenter = 0;
	kprobe_opcode_t *addr = NULL, *ssaddr = 0;
	struct kprobe_ctlblk *kcb;
	
	nCount++;
	/* We're in an interrupt, but this is clear and BUG()-safe. */
#ifdef _DEBUG
	gSilent = 1;
#endif
#if defined(CONFIG_MIPS)
	addr = (kprobe_opcode_t *) regs->cp0_epc;
	DBPRINTF ("regs->regs[ 31 ] = 0x%lx\n", regs->regs[31]);
#elif defined(CONFIG_ARM)
	addr = (kprobe_opcode_t *) (regs->uregs[15] - 4);
	DBPRINTF ("KPROBE[%lu]: regs->uregs[15] = 0x%lx addr = 0x%p\n", nCount, regs->uregs[15], addr);
	regs->uregs[15] -= 4;
	//DBPRINTF("regs->uregs[14] = 0x%lx\n", regs->uregs[14]);
#else
#error implement how to get exception address for this arch!!!
#endif // ARCH

	preempt_disable ();

	kcb = get_kprobe_ctlblk ();

	if (user_mode (regs))
	{
#ifdef _DEBUG
		gSilent = 0;
#endif
		//DBPRINTF("exception[%lu] from user mode %s/%u addr %p (%lx).", nCount, current->comm, current->pid, addr, regs->uregs[14]);
		pid = current->tgid;
	}

	/* Check we're not actually recursing */
	if (kprobe_running ())
	{
		DBPRINTF ("lock???");
		p = get_kprobe (addr, pid, current);
		if (p)
		{
			if(!pid && (addr == (kprobe_opcode_t *)kretprobe_trampoline)){
				save_previous_kprobe (kcb, p);
				kcb->kprobe_status = KPROBE_REENTER;
				reenter = 1;
			}
			else {
				/* We have reentered the kprobe_handler(), since
				 * another probe was hit while within the handler.
				 * We here save the original kprobes variables and
				 * just single step on the instruction of the new probe
				 * without calling any user handlers.
				 */
				if(!p->ainsn.boostable){
					save_previous_kprobe (kcb, p);
					set_current_kprobe (p, regs, kcb);
				}
				kprobes_inc_nmissed_count (p);
				prepare_singlestep (p, regs);
				if(!p->ainsn.boostable)
					kcb->kprobe_status = KPROBE_REENTER;
				preempt_enable_no_resched ();
				return 1;
			}
		}
		else
		{
			if(pid) { //we can reenter probe upon uretprobe exception   
				DBPRINTF ("check for UNDEF_INSTRUCTION %p\n", addr);
				// UNDEF_INSTRUCTION from user space
				p = get_kprobe_by_insn_slot (addr-UPROBES_TRAMP_RET_BREAK_IDX, pid, current);
				if (p) {
					save_previous_kprobe (kcb, p);
					kcb->kprobe_status = KPROBE_REENTER;
					reenter = 1;
					retprobe = 1;
					DBPRINTF ("uretprobe %p\n", addr);
				}
			}
			if(!p) {
				p = __get_cpu_var (current_kprobe);
#ifdef _DEBUG
				if (p->tgid) gSilent = 0;
#endif
				DBPRINTF ("kprobe_running !!! p = 0x%p p->break_handler = 0x%p", p, p->break_handler);
				/*if (p->break_handler && p->break_handler(p, regs)) {
				   DBPRINTF("kprobe_running !!! goto ss");
				   goto ss_probe;
				   } */			
				DBPRINTF ("unknown uprobe at %p cur at %p/%p\n", addr, p->addr, p->ainsn.insn);
				if(pid)
					ssaddr = p->ainsn.insn + UPROBES_TRAMP_SS_BREAK_IDX;
				else
					ssaddr = p->ainsn.insn + KPROBES_TRAMP_SS_BREAK_IDX;				
				if (addr == ssaddr)
				{
#if defined(CONFIG_ARM)
					regs->uregs[15] = (unsigned long) (p->addr + 1);
					DBPRINTF ("finish step at %p cur at %p/%p, redirect to %lx\n", addr, p->addr, p->ainsn.insn, regs->uregs[15]);
#elif defined(CONFIG_MIPS)
					regs->cp0_epc = (unsigned long) (p->addr + 1);
					DBPRINTF ("finish step at %p cur at %p/%p, redirect to %lx\n", addr, p->addr, p->ainsn.insn, regs->cp0_epc);
#else
#warning uprobe single step is not implemented for this arch!!!
#endif
					if (kcb->kprobe_status == KPROBE_REENTER) {
						restore_previous_kprobe (kcb);
					}
					else {
						reset_current_kprobe ();
					}
				}
				DBPRINTF ("kprobe_running !!! goto no");
				ret = 1;
				/* If it's not ours, can't be delete race, (we hold lock). */
				DBPRINTF ("no_kprobe");
				goto no_kprobe;
			}
		}
	}

	//if(einsn != UNDEF_INSTRUCTION) {
	DBPRINTF ("get_kprobe %p-%d", addr, pid);
	if (!p)
		p = get_kprobe (addr, pid, current);
	if (!p)
	{
		if(pid) {
			DBPRINTF ("search UNDEF_INSTRUCTION %p\n", addr);
			// UNDEF_INSTRUCTION from user space
			p = get_kprobe_by_insn_slot (addr-UPROBES_TRAMP_RET_BREAK_IDX, pid, current);
			if (!p) {
				/* Not one of ours: let kernel handle it */
				DBPRINTF ("no_kprobe");
				//printk("no_kprobe2 ret = %d\n", ret);
				goto no_kprobe;
			}
			retprobe = 1;
			DBPRINTF ("uretprobe %p\n", addr);
		}
		else {
			/* Not one of ours: let kernel handle it */
			DBPRINTF ("no_kprobe");
			//printk("no_kprobe2 ret = %d\n", ret);
			goto no_kprobe;
		}
	}
#ifdef _DEBUG
	if (p->tgid) gSilent = 0;
#endif
	
	set_current_kprobe (p, regs, kcb);
	if(!reenter)
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;

	if (retprobe)		//(einsn == UNDEF_INSTRUCTION)
		ret = trampoline_probe_handler (p, regs);
	else if (p->pre_handler)
	{
		ret = p->pre_handler (p, regs);
		if(!p->ainsn.boostable)
			kcb->kprobe_status = KPROBE_HIT_SS;
		else if(p->pre_handler != trampoline_probe_handler)
			reset_current_kprobe ();			
	}

	if (ret)
	{
		DBPRINTF ("p->pre_handler[%lu] 1", nCount);
		/* handler has already set things up, so skip ss setup */
		return 1;
	}
	DBPRINTF ("p->pre_handler 0");

no_kprobe:
	preempt_enable_no_resched ();
#ifdef _DEBUG
	gSilent = 1;
#endif
	return ret;
}
#endif

extern struct kretprobe *sched_rp;

static void patch_suspended_task_ret_addr(struct task_struct *p, struct kretprobe *rp)
{
	struct kretprobe_instance *ri = NULL;
	struct hlist_node *node, *tmp; 
	struct hlist_head *head;
	unsigned long flags;
	int found = 0;
	
	spin_lock_irqsave (&kretprobe_lock, flags); 
	head = kretprobe_inst_table_head (p);
	hlist_for_each_entry_safe (ri, node, tmp, head, hlist){
		if ((ri->rp == rp) && (p == ri->task)){
			found = 1;
			break; 
		}
	}
	spin_unlock_irqrestore (&kretprobe_lock, flags); 

#ifdef CONFIG_ARM

#ifndef task_thread_info
#define task_thread_info(task) (task)->thread_info
#endif // task_thread_info

	if (found){
		// update PC
		if(thread_saved_pc(p) != (unsigned long)&kretprobe_trampoline){
			ri->ret_addr = (kprobe_opcode_t *)thread_saved_pc(p);
			task_thread_info(p)->cpu_context.pc = (unsigned long) &kretprobe_trampoline;
		}
		return; 
	}
	
	if ((ri = get_free_rp_inst(rp)) != NULL)
	{
		ri->rp = rp; 
		ri->rp2 = NULL; 
		ri->task = p;
		ri->ret_addr = (kprobe_opcode_t *)thread_saved_pc(p);
		task_thread_info(p)->cpu_context.pc = (unsigned long) &kretprobe_trampoline;
		add_rp_inst (ri);
//		printk("change2 saved pc %p->%p for %d/%d/%p\n", ri->ret_addr, &kretprobe_trampoline, p->tgid, p->pid, p);
	}
	else{
		printk("no ri for %d\n", p->pid);
		BUG();				
	}
#endif // CONFIG_ARM
}

typedef kprobe_opcode_t (*entry_point_t) (unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
int
setjmp_pre_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct jprobe *jp = container_of (p, struct jprobe, kp);
	kprobe_pre_entry_handler_t pre_entry;
	entry_point_t entry;
	
#if defined(CONFIG_X86)
	unsigned long addr, args[6];	
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	DBPRINTF ("setjmp_pre_handler %p:%d", p->addr, p->tgid);
	pre_entry = (kprobe_pre_entry_handler_t) jp->pre_entry;
	entry = (entry_point_t) jp->entry;
	if(p->tgid) {
		regs->EREG (flags) &= ~IF_MASK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		trace_hardirqs_off ();
#endif
		if (p->tgid == current->tgid)
		{
			// read first 6 args from stack
			if (!read_proc_vm_atomic (current, regs->EREG(sp)+4, args, sizeof(args)))
				panic ("failed to read user space func arguments %lx!\n", regs->EREG(sp)+4);
			if (pre_entry)
				p->ss_addr = pre_entry (jp->priv_arg, regs);
			if (entry)
				entry (args[0], args[1], args[2], args[3], args[4], args[5]);
		}
		else
			uprobe_return ();
		
		return 2;
	}
	else {
		kcb->jprobe_saved_regs = *regs;
		kcb->jprobe_saved_esp = &regs->EREG (sp);
		addr = (unsigned long) (kcb->jprobe_saved_esp);
	
		/*
		 * TBD: As Linus pointed out, gcc assumes that the callee
		 * owns the argument space and could overwrite it, e.g.
		 * tailcall optimization. So, to be absolutely safe
		 * we also save and restore enough stack bytes to cover
		 * the argument area.
		 */
		memcpy (kcb->jprobes_stack, (kprobe_opcode_t *) addr, MIN_STACK_SIZE (addr));
		regs->EREG (flags) &= ~IF_MASK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		trace_hardirqs_off ();
#endif
		if (pre_entry)
			p->ss_addr = pre_entry (jp->priv_arg, regs);
		regs->EREG (ip) = (unsigned long) (jp->entry);
	}
	
	return 1;
#else //!CONFIG_X86
# ifdef REENTER
	p = __get_cpu_var (current_kprobe);
# endif

	DBPRINTF ("pjp = 0x%p jp->entry = 0x%p", jp, jp->entry);
	entry = (entry_point_t) jp->entry;
	pre_entry = (kprobe_pre_entry_handler_t) jp->pre_entry;
	//if(!entry)
	//      DIE("entry NULL", regs)
	DBPRINTF ("entry = 0x%p jp->entry = 0x%p", entry, jp->entry);

	//call handler for all kernel probes and user space ones which belong to current tgid
	if (!p->tgid || (p->tgid == current->tgid))
	{		
		if(!p->tgid && (p->addr == sched_addr) && sched_rp){
			struct task_struct *p, *g;
			rcu_read_lock();
			//swapper task
			if(current != &init_task)
				patch_suspended_task_ret_addr(&init_task, sched_rp);
			// other tasks
			do_each_thread(g, p){
				if(p == current)
					continue;									
				patch_suspended_task_ret_addr(p, sched_rp);
			} while_each_thread(g, p);
			rcu_read_unlock();
		}
		if (pre_entry)
			p->ss_addr = (void *)pre_entry (jp->priv_arg, regs);
		if (entry){
# if defined(CONFIG_MIPS)
			entry (regs->regs[4], regs->regs[5], regs->regs[6], regs->regs[7], regs->regs[8], regs->regs[9]);
# elif defined(CONFIG_ARM)
			entry (regs->ARM_r0, regs->ARM_r1, regs->ARM_r2, regs->ARM_r3, regs->ARM_r4, regs->ARM_r5);
# endif	// ARCH
		}
		else {
			if (p->tgid)
				uprobe_return ();
			else
				jprobe_return ();
		}
	}
	else if (p->tgid)
		uprobe_return ();

	prepare_singlestep (p, regs);
# ifdef _DEBUG
	p->step_count++;
# endif
	
	return 1;	
#endif //!CONFIG_X86
}

void __kprobes
jprobe_return (void)
{
#if defined(CONFIG_X86)
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	asm volatile("       xchgl   %%ebx,%%esp     \n"
		      	"       int3			\n"
		      	"       .globl jprobe_return_end	\n"
				"       jprobe_return_end:	\n"
				"       nop			\n"::"b" (kcb->jprobe_saved_esp):"memory");
#else
	preempt_enable_no_resched();
#endif
}

void __kprobes
uprobe_return (void)
{
#if defined(CONFIG_X86)
	/*struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	asm volatile("       xchgl   %%ebx,%%esp     \n"
		      	"       int3			\n"
		      	"       .globl jprobe_return_end	\n"
				"       jprobe_return_end:	\n"
				"       nop			\n"::"b" (kcb->jprobe_saved_esp):"memory");*/
#else
	preempt_enable_no_resched ();
#endif
}

#if defined(CONFIG_X86)
/*
 * Called after single-stepping.  p->addr is the address of the
 * instruction whose first byte has been replaced by the "int 3"
 * instruction.  To avoid the SMP problems that can occur when we
 * temporarily put back the original opcode to single-step, we
 * single-stepped a copy of the instruction.  The address of this
 * copy is p->ainsn.insn.
 *
 * This function prepares to return from the post-single-step
 * interrupt.  We have to fix up the stack as follows:
 *
 * 0) Except in the case of absolute or indirect jump or call instructions,
 * the new eip is relative to the copied instruction.  We need to make
 * it relative to the original instruction.
 *
 * 1) If the single-stepped instruction was pushfl, then the TF and IF
 * flags are set in the just-pushed eflags, and may need to be cleared.
 *
 * 2) If the single-stepped instruction was a call, the return address
 * that is atop the stack is the address following the copied instruction.
 * We need to make it the address following the original instruction.
 *
 * This function also checks instruction size for preparing direct execution.
 */
static void __kprobes
resume_execution (struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb)
{
	unsigned long *tos, tos_dword = 0;
	unsigned long copy_eip = (unsigned long) p->ainsn.insn;
	unsigned long orig_eip = (unsigned long) p->addr;
	kprobe_opcode_t insns[2];

	regs->EREG (flags) &= ~TF_MASK;

	if(p->tgid){
		tos = (unsigned long *) &tos_dword;
		if (!read_proc_vm_atomic (current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
			panic ("failed to read dword from top of the user space stack %lx!\n", regs->EREG (sp));
		if (!read_proc_vm_atomic (current, (unsigned long)p->ainsn.insn, insns, 2*sizeof(kprobe_opcode_t)))
			panic ("failed to read first 2 opcodes of instruction copy from user space %p!\n", p->ainsn.insn);
	}
	else {
		tos = (unsigned long *) &regs->EREG (sp);
		insns[0] = p->ainsn.insn[0];
		insns[1] = p->ainsn.insn[1];
	}
	
	switch (insns[0])
	{
	case 0x9c:		/* pushfl */
		*tos &= ~(TF_MASK | IF_MASK);
		*tos |= kcb->kprobe_old_eflags;
		break;
	case 0xc2:		/* iret/ret/lret */
	case 0xc3:
	case 0xca:
	case 0xcb:
	case 0xcf:
	case 0xea:		/* jmp absolute -- eip is correct */
		/* eip is already adjusted, no more changes required */
		p->ainsn.boostable = 1;
		goto no_change;
	case 0xe8:		/* call relative - Fix return addr */
		*tos = orig_eip + (*tos - copy_eip);
		break;
	case 0x9a:		/* call absolute -- same as call absolute, indirect */
		*tos = orig_eip + (*tos - copy_eip);
		if(p->tgid){
			if (!write_proc_vm_atomic (current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
				panic ("failed to write dword to top of the user space stack %lx!\n", regs->EREG (sp));
		}
		goto no_change;
	case 0xff:
		if ((insns[1] & 0x30) == 0x10)
		{
			/*
			 * call absolute, indirect
			 * Fix return addr; eip is correct.
			 * But this is not boostable
			 */
			*tos = orig_eip + (*tos - copy_eip);
			if(p->tgid){
				if (!write_proc_vm_atomic (current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
					panic ("failed to write dword to top of the user space stack %lx!\n", regs->EREG (sp));
			}
			goto no_change;
		}
		else if (((insns[1] & 0x31) == 0x20) ||	/* jmp near, absolute indirect */
			     ((insns[1] & 0x31) == 0x21))
		{		/* jmp far, absolute indirect */
			/* eip is correct. And this is boostable */
			p->ainsn.boostable = 1;
			goto no_change;
		}
	default:
		break;
	}

	if(p->tgid){
		if (!write_proc_vm_atomic (current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
			panic ("failed to write dword to top of the user space stack %lx!\n", regs->EREG (sp));
	}

	if (p->ainsn.boostable == 0)
	{
		if ((regs->EREG (ip) > copy_eip) && (regs->EREG (ip) - copy_eip) + 5 < MAX_INSN_SIZE)
		{
			/*
			 * These instructions can be executed directly if it
			 * jumps back to correct address.
			 */			
			if(p->tgid)
				set_user_jmp_op ((void *) regs->EREG (ip), (void *) orig_eip + (regs->EREG (ip) - copy_eip));				
			else
				set_jmp_op ((void *) regs->EREG (ip), (void *) orig_eip + (regs->EREG (ip) - copy_eip));
			p->ainsn.boostable = 1;
		}
		else
		{
			p->ainsn.boostable = -1;
		}
	}

	regs->EREG (ip) = orig_eip + (regs->EREG (ip) - copy_eip);

no_change:
	return;
}

/*
 * Interrupts are disabled on entry as trap1 is an interrupt gate and they
 * remain disabled thoroughout this function.
 */
static int __kprobes
post_kprobe_handler (struct pt_regs *regs)
{
	struct kprobe *cur = kprobe_running ();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	if (!cur)
		return 0;
	if ((kcb->kprobe_status != KPROBE_REENTER) && cur->post_handler)
	{
		kcb->kprobe_status = KPROBE_HIT_SSDONE;
		cur->post_handler (cur, regs, 0);
	}
	
	resume_execution (cur, regs, kcb);
	regs->EREG (flags) |= kcb->kprobe_saved_eflags;
#ifndef CONFIG_X86
	trace_hardirqs_fixup_flags (regs->EREG (flags));
#endif // CONFIG_X86
	/*Restore back the original saved kprobes variables and continue. */
	if (kcb->kprobe_status == KPROBE_REENTER)
	{
		restore_previous_kprobe (kcb);
		goto out;
	}
	reset_current_kprobe ();
out:
	preempt_enable_no_resched ();

	/*
	 * if somebody else is singlestepping across a probe point, eflags
	 * will have TF set, in which case, continue the remaining processing
	 * of do_debug, as if this is not a probe hit.
	 */
	if (regs->EREG (flags) & TF_MASK)
		return 0;

	return 1;
}

static int __kprobes
kprobe_fault_handler (struct pt_regs *regs, int trapnr)
{
	struct kprobe *cur = kprobe_running ();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	switch (kcb->kprobe_status)
	{
	case KPROBE_HIT_SS:
	case KPROBE_REENTER:
		/*
		 * We are here because the instruction being single
		 * stepped caused a page fault. We reset the current
		 * kprobe and the eip points back to the probe address
		 * and allow the page fault handler to continue as a
		 * normal page fault.
		 */
		regs->EREG (ip) = (unsigned long) cur->addr;
		regs->EREG (flags) |= kcb->kprobe_old_eflags;
		if (kcb->kprobe_status == KPROBE_REENTER)
			restore_previous_kprobe (kcb);
		else
			reset_current_kprobe ();
		preempt_enable_no_resched ();
		break;
	case KPROBE_HIT_ACTIVE:
	case KPROBE_HIT_SSDONE:
		/*
		 * We increment the nmissed count for accounting,
		 * we can also use npre/npostfault count for accouting
		 * these specific fault cases.
		 */
		kprobes_inc_nmissed_count (cur);

		/*
		 * We come here because instructions in the pre/post
		 * handler caused the page_fault, this could happen
		 * if handler tries to access user space by
		 * copy_from_user(), get_user() etc. Let the
		 * user-specified handler try to fix it first.
		 */
		if (cur->fault_handler && cur->fault_handler (cur, regs, trapnr))
			return 1;

		/*
		 * In case the user-specified fault handler returned
		 * zero, try to fix up.
		 */
		if (fixup_exception (regs))
			return 1;

		/*
		 * fixup_exception() could not handle it,
		 * Let do_page_fault() fix it.
		 */
		break;
	default:
		break;
	}
	return 0;
}

int
kprobe_exceptions_notify (struct notifier_block *self, unsigned long val, void *data)
{
	struct die_args *args = (struct die_args *) data;
	int ret = NOTIFY_DONE;

	DBPRINTF ("val = %ld, data = 0x%X", val, (unsigned int) data);

	/*if (args->regs && user_mode_vm (args->regs))
		return ret;*/

	DBPRINTF ("switch (val) %lu %d %d", val, DIE_INT3, DIE_TRAP);
	switch (val)
	{
//#ifdef CONFIG_KPROBES
//      case DIE_INT3:
//#else
	case DIE_TRAP:
//#endif
		DBPRINTF ("before kprobe_handler ret=%d %p", ret, args->regs);
		if (kprobe_handler (args->regs))
			ret = NOTIFY_STOP;
		DBPRINTF ("after kprobe_handler ret=%d %p", ret, args->regs);
		break;
	case DIE_DEBUG:
		if (post_kprobe_handler (args->regs))
			ret = NOTIFY_STOP;
		break;
	case DIE_GPF:
		// kprobe_running() needs smp_processor_id()
		preempt_disable ();
		if (kprobe_running () && kprobe_fault_handler (args->regs, args->trapnr))
			ret = NOTIFY_STOP;
		preempt_enable ();
		break;
	default:
		break;
	}
	DBPRINTF ("ret=%d", ret);
	if(ret == NOTIFY_STOP)
		handled_exceptions++;
	
	return ret;
}
#endif // CONFIG_X86

int
longjmp_break_handler (struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_X86)
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();
	u8 *addr = (u8 *) (regs->EREG (ip) - 1);
	unsigned long stack_addr = (unsigned long) (kcb->jprobe_saved_esp);
	struct jprobe *jp = container_of (p, struct jprobe, kp);

	DBPRINTF ("p = %p\n", p);

	if ((addr > (u8 *) jprobe_return) && (addr < (u8 *) jprobe_return_end))
	{
		if ((unsigned long *)(&regs->EREG(sp)) != kcb->jprobe_saved_esp)
		{
			struct pt_regs *saved_regs = &kcb->jprobe_saved_regs;
			printk ("current esp %p does not match saved esp %p\n", &regs->EREG (sp), kcb->jprobe_saved_esp);
			printk ("Saved registers for jprobe %p\n", jp);
			show_registers (saved_regs);
			printk ("Current registers\n");
			show_registers (regs);
			panic("BUG");
			//BUG ();			
		}
		*regs = kcb->jprobe_saved_regs;
		memcpy ((kprobe_opcode_t *) stack_addr, kcb->jprobes_stack, MIN_STACK_SIZE (stack_addr));
		preempt_enable_no_resched ();
		return 1;
	}
#else //non x86
	DBPRINTF ("p = %p\n", p);
	//DBPRINTF("p->opcode = 0x%lx *p->addr = 0x%lx p->addr = 0x%p\n", p->opcode, p->pid?*kaddr[0]:*p->addr, p->pid?kaddr[0]:p->addr);
# ifndef REENTER
	//kprobe_opcode_t insn = BREAKPOINT_INSTRUCTION;
	kprobe_opcode_t insns[2];

	if (p->pid)
	{
		insns[0] = BREAKPOINT_INSTRUCTION;
		insns[1] = p->opcode;
		//p->opcode = *p->addr;
		if (read_proc_vm_atomic (current, (unsigned long) (p->addr), &(p->opcode), sizeof (p->opcode)) < sizeof (p->opcode))
		{
			printk ("ERROR[%lu]: failed to read vm of proc %s/%u addr %p.", nCount, current->comm, current->pid, p->addr);
			return -1;
		}
		//*p->addr = BREAKPOINT_INSTRUCTION;
		//*(p->addr+1) = p->opcode;             
		if (write_proc_vm_atomic (current, (unsigned long) (p->addr), insns, sizeof (insns)) < sizeof (insns))
		{
			printk ("ERROR[%lu]: failed to write vm of proc %s/%u addr %p.", nCount, current->comm, current->pid, p->addr);
			return -1;
		}
	}
	else
	{
		DBPRINTF ("p->opcode = 0x%lx *p->addr = 0x%lx p->addr = 0x%p\n", p->opcode, *p->addr, p->addr);
		*(p->addr + 1) = p->opcode;
		p->opcode = *p->addr;
		*p->addr = BREAKPOINT_INSTRUCTION;
		flush_icache_range ((unsigned int) p->addr, (unsigned int) (((unsigned int) p->addr) + (sizeof (kprobe_opcode_t) * 2)));
	}

	reset_current_kprobe ();
# endif	//!reenter
#endif //non x86

	return 0;
}

void __kprobes
arch_arm_kprobe (struct kprobe *p)
{
#if defined(CONFIG_X86)
	text_poke (p->addr, ((unsigned char[])
			     {BREAKPOINT_INSTRUCTION}), 1);
#else
	*p->addr = BREAKPOINT_INSTRUCTION;
	flush_icache_range ((unsigned long) p->addr, (unsigned long) p->addr + sizeof (kprobe_opcode_t));
#endif
}

void __kprobes
arch_disarm_kprobe (struct kprobe *p)
{
#if defined(CONFIG_X86)
	text_poke (p->addr, &p->opcode, 1);
#else
	*p->addr = p->opcode;
	flush_icache_range ((unsigned long) p->addr, (unsigned long) p->addr + sizeof (kprobe_opcode_t));
#endif
}

void __kprobes
arch_arm_uprobe (struct kprobe *p, struct task_struct *tsk)
{
	kprobe_opcode_t insn = BREAKPOINT_INSTRUCTION;

	if (!write_proc_vm_atomic (tsk, (unsigned long) p->addr, &insn, sizeof (insn)))
		panic ("failed to write memory %p!\n", p->addr);
}

void __kprobes
arch_arm_uretprobe (struct kretprobe *p, struct task_struct *tsk)
{
}

void __kprobes
arch_disarm_uprobe (struct kprobe *p, struct task_struct *tsk)
{
	if (!write_proc_vm_atomic (tsk, (unsigned long) p->addr, &p->opcode, sizeof (p->opcode)))
		panic ("failed to write memory %p!\n", p->addr);
}

void __kprobes
arch_disarm_uretprobe (struct kretprobe *p, struct task_struct *tsk)//, struct vm_area_struct *vma, struct page *page, unsigned long *kaddr)
{
}

#if defined(CONFIG_X86)
/*fastcall*/ void *__kprobes trampoline_probe_handler_x86 (struct pt_regs *regs)
{
	return (void *)trampoline_probe_handler(NULL, regs);
}
#endif

/*
 * Function return probe trampoline:
 * 	- init_kprobes() establishes a probepoint here
 * 	- When the probed function returns, this probe
 * 		causes the handlers to fire
 */
void
kretprobe_trampoline_holder (void)
{
	asm volatile (".global kretprobe_trampoline\n" 
			  "kretprobe_trampoline:\n"
#if defined(CONFIG_MIPS)
		      "nop\n" 
			  "nop\n");
#elif defined(CONFIG_ARM)
		      "nop\n" 
			  "nop\n" 
			  "mov pc, r14\n");
#elif defined(CONFIG_X86)
		      "	pushf\n"
		      /* skip cs, eip, orig_eax */
		      "	subl $12, %esp\n"
		      "	pushl %fs\n"
		      "	pushl %ds\n"
		      "	pushl %es\n"
		      "	pushl %eax\n" 
		      "	pushl %ebp\n" 
		      "	pushl %edi\n" 
		      "	pushl %esi\n" 
		      "	pushl %edx\n" 
		      "	pushl %ecx\n" 
		      "	pushl %ebx\n" 
		      "	movl %esp, %eax\n" 
		      "	call trampoline_probe_handler_x86\n"
		      /* move eflags to cs */
		      "	movl 52(%esp), %edx\n" 
		      "	movl %edx, 48(%esp)\n"
		      /* save true return address on eflags */
		      "	movl %eax, 52(%esp)\n" 
		      "	popl %ebx\n" ""
		      "	popl %ecx\n" 
		      "	popl %edx\n" 
		      "	popl %esi\n" 
		      "	popl %edi\n" 
		      "	popl %ebp\n" 
		      "	popl %eax\n"
		      /* skip eip, orig_eax, es, ds, fs */
		      "	addl $20, %esp\n" 
		      "	popf\n" 
			  "	ret\n");
#else
#	error kretprobe_trampoline_holder is not implemented for this arch!!!
#endif				// ARCH
}

/*
 * Called when the probe at kretprobe trampoline is hit
 */
int __kprobes trampoline_probe_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct kretprobe_instance *ri = NULL; 
	struct hlist_head *head, empty_rp; 
	struct hlist_node *node, *tmp; 
	unsigned long flags, orig_ret_address = 0;
	unsigned long trampoline_address = (unsigned long) &kretprobe_trampoline;
	struct kretprobe *crp = NULL; 
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();
	
	DBPRINTF ("start");

	if (p && p->tgid){
		// in case of user space retprobe trampoline is at the Nth instruction of US tramp 
		trampoline_address = (unsigned long)(p->ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
	}

	INIT_HLIST_HEAD (&empty_rp); 
	spin_lock_irqsave (&kretprobe_lock, flags); 
	head = kretprobe_inst_table_head (current);
#if defined(CONFIG_X86)
	if(!p){ // X86 kernel space
		DBPRINTF ("regs %p", regs);
		/* fixup registers */
		regs->XREG (cs) = __KERNEL_CS | get_kernel_rpl (); 
		regs->EREG (ip) = trampoline_address; 
		regs->ORIG_EAX_REG = 0xffffffff;
	}
#endif
	/*
	 * It is possible to have multiple instances associated with a given
	 * task either because an multiple functions in the call path
	 * have a return probe installed on them, and/or more then one 
	 * return probe was registered for a target function.
	 *
	 * We can handle this because:
	 *     - instances are always inserted at the head of the list
	 *     - when multiple return probes are registered for the same
	 *       function, the first instance's ret_addr will point to the
	 *       real return address, and all the rest will point to
	 *       kretprobe_trampoline
	 */
	hlist_for_each_entry_safe (ri, node, tmp, head, hlist)
	{
		if (ri->task != current)
			/* another task is sharing our hash bucket */
			continue; 
		if (ri->rp && ri->rp->handler){
#if defined(CONFIG_X86)
			if(!p){ // X86 kernel space
				__get_cpu_var (current_kprobe) = &ri->rp->kp; 
				get_kprobe_ctlblk ()->kprobe_status = KPROBE_HIT_ACTIVE;
			}
#endif
			ri->rp->handler (ri, regs, ri->rp->priv_arg);
#if defined(CONFIG_X86)
			if(!p) // X86 kernel space
				__get_cpu_var (current_kprobe) = NULL;
#endif
		}

		orig_ret_address = (unsigned long) ri->ret_addr; 
		recycle_rp_inst (ri, &empty_rp); 
		if (orig_ret_address != trampoline_address)
			/*
			 * This is the real return address. Any other
			 * instances associated with this task are for
			 * other calls deeper on the call stack
			 */
			break;
	}
	kretprobe_assert (ri, orig_ret_address, trampoline_address);
	//BUG_ON(!orig_ret_address || (orig_ret_address == trampoline_address));
	if (trampoline_address != (unsigned long) &kretprobe_trampoline){
		if (ri->rp2) BUG_ON (ri->rp2->kp.tgid == 0);
		if (ri->rp) BUG_ON (ri->rp->kp.tgid == 0);
		else if (ri->rp2) BUG_ON (ri->rp2->kp.tgid == 0);
	}
	if ((ri->rp && ri->rp->kp.tgid) || (ri->rp2 && ri->rp2->kp.tgid)) 
		BUG_ON (trampoline_address == (unsigned long) &kretprobe_trampoline);
#if defined(CONFIG_MIPS)
	regs->regs[31] = orig_ret_address;
	DBPRINTF ("regs->cp0_epc = 0x%lx", regs->cp0_epc); 
	if (trampoline_address != (unsigned long) &kretprobe_trampoline) 
		regs->cp0_epc = orig_ret_address;
	else
		regs->cp0_epc = regs->cp0_epc + 4; 
	DBPRINTF ("regs->cp0_epc = 0x%lx", regs->cp0_epc); 
	DBPRINTF ("regs->cp0_status = 0x%lx", regs->cp0_status);
#elif defined(CONFIG_ARM)
	regs->uregs[14] = orig_ret_address; 
	DBPRINTF ("regs->uregs[14] = 0x%lx\n", regs->uregs[14]);
	DBPRINTF ("regs->uregs[15] = 0x%lx\n", regs->uregs[15]); 
	if (trampoline_address != (unsigned long) &kretprobe_trampoline) 
		regs->uregs[15] = orig_ret_address;
	else
		regs->uregs[15] += 4;
	DBPRINTF ("regs->uregs[15] = 0x%lx\n", regs->uregs[15]);
#elif defined(CONFIG_X86)
	if(p){ // X86 user space
		regs->EREG(ip) = orig_ret_address; 
		//printk (" uretprobe regs->eip = 0x%lx\n", regs->EREG(ip));
	}
#endif // ARCH

	if(p){ // ARM, MIPS, X86 user space
		if (kcb->kprobe_status == KPROBE_REENTER)
			restore_previous_kprobe (kcb);
		else
			reset_current_kprobe ();
			
		//TODO: test - enter function, delete us retprobe, exit function 
		// for user space retprobes only - deferred deletion
		if (trampoline_address != (unsigned long) &kretprobe_trampoline)
		{
			// if we are not at the end of the list and current retprobe should be disarmed 
			if (node && ri->rp2)
			{
				crp = ri->rp2;
				/*sprintf(die_msg, "deferred disarm p->addr = %p [%lx %lx %lx]\n", 
				 crp->kp.addr, *kaddrs[0], *kaddrs[1], *kaddrs[2]);
				 DIE(die_msg, regs); */
				// look for other instances for the same retprobe
				hlist_for_each_entry_continue (ri, node, hlist)
				{
					if (ri->task != current) 
						continue;	/* another task is sharing our hash bucket */
					if (ri->rp2 == crp)	//if instance belong to the same retprobe
						break;
				}
				if (!node)
				{	// if there are no more instances for this retprobe
					// delete retprobe
					DBPRINTF ("defered retprobe deletion p->addr = %p", crp->kp.addr);
					unregister_uprobe (&crp->kp, current, 1);
					kfree (crp);
				}
			}
		}
	}
	
	spin_unlock_irqrestore (&kretprobe_lock, flags); 
	hlist_for_each_entry_safe (ri, node, tmp, &empty_rp, hlist)
	{
		hlist_del (&ri->hlist); 
		kfree (ri);
	}
#if defined(CONFIG_X86)
	if(!p) // X86 kernel space
		return (int)orig_ret_address;
#endif
	preempt_enable_no_resched ();
	/*
	 * By returning a non-zero value, we are telling
	 * kprobe_handler() that we don't want the post_handler
	 * to run (and have re-enabled preemption)
	 */
	return 1;
}

/* Called with kretprobe_lock held */
void __kprobes __arch_prepare_kretprobe (struct kretprobe *rp, struct pt_regs *regs)
{
	struct kretprobe_instance *ri;

	DBPRINTF ("start\n");
	//TODO: test - remove retprobe after func entry but before its exit
	if ((ri = get_free_rp_inst (rp)) != NULL)
	{
		ri->rp = rp; 
		ri->rp2 = NULL; 
		ri->task = current;
#if defined(CONFIG_MIPS)
		ri->ret_addr = (kprobe_opcode_t *) regs->regs[31];
		if (rp->kp.tgid)
			regs->regs[31] = (unsigned long) (rp->kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
		else	/* Replace the return addr with trampoline addr */
			regs->regs[31] = (unsigned long) &kretprobe_trampoline;
#elif defined(CONFIG_ARM)
		ri->ret_addr = (kprobe_opcode_t *) regs->uregs[14];
		if (rp->kp.tgid)
			regs->uregs[14] = (unsigned long) (rp->kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
		else	/* Replace the return addr with trampoline addr */
			regs->uregs[14] = (unsigned long) &kretprobe_trampoline; 
		DBPRINTF ("ret addr set to %p->%lx\n", ri->ret_addr, regs->uregs[14]);
#elif defined(CONFIG_X86)
		/* Replace the return addr with trampoline addr */
		if (rp->kp.tgid){
			unsigned long ra = (unsigned long) (rp->kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);/*, stack[6];
			if (!read_proc_vm_atomic (current, regs->EREG(sp), stack, sizeof(stack)))
				panic ("failed to read user space func stack %lx!\n", regs->EREG(sp));
			printk("stack: %lx %lx %lx %lx %lx %lx\n", stack[0], stack[1], stack[2], stack[3], stack[4], stack[5]);*/
			if (!read_proc_vm_atomic (current, regs->EREG(sp), &(ri->ret_addr), sizeof(ri->ret_addr)))
				panic ("failed to read user space func ra %lx!\n", regs->EREG(sp));
			if (!write_proc_vm_atomic (current, regs->EREG(sp), &ra, sizeof(ra)))
				panic ("failed to write user space func ra %lx!\n", regs->EREG(sp));
			//printk("__arch_prepare_kretprobe: ra %lx %p->%lx\n",regs->EREG(sp), ri->ret_addr, ra);
		}
		else {
			unsigned long *sara = (unsigned long *)&regs->EREG(sp);
			ri->ret_addr = (kprobe_opcode_t *)*sara;
			*sara = (unsigned long)&kretprobe_trampoline;
			DBPRINTF ("ra loc %p, origr_ra %p new ra %lx\n", sara, ri->ret_addr, *sara);
		}		
#else
#error  __arch_prepare_kretprobe is not implemented for this arch!!!
#endif // ARCH
		add_rp_inst (ri);
	}
	else {
		DBPRINTF ("WARNING: missed retprobe %p\n", rp->kp.addr);
		rp->nmissed++;
	}
}

#if !defined(CONFIG_X86)
static struct kprobe trampoline_p =
{
		.addr = (kprobe_opcode_t *) & kretprobe_trampoline,
		.pre_handler = trampoline_probe_handler
};
#endif

/*static void do_exit_probe_handler (void)
{
	printk("do_exit_probe_handler\n");
	unregister_all_uprobes(current, 1);
	jprobe_return();
}

static struct jprobe do_exit_p =
{
		.entry = (kprobe_pre_entry_handler_t)do_exit_probe_handler
};*/

//--------------------- Declaration of module dependencies ------------------------//
#define DECLARE_MOD_FUNC_DEP(name, ret, ...) ret(*__ref_##name)(__VA_ARGS__)
#define DECLARE_MOD_CB_DEP(name, ret, ...) ret(*name)(__VA_ARGS__)
// persistent deps
DECLARE_MOD_CB_DEP(kallsyms_search, unsigned long, const char *name);
DECLARE_MOD_FUNC_DEP(access_process_vm, int, struct task_struct * tsk, unsigned long addr, void *buf, int len, int write);

DECLARE_MOD_FUNC_DEP(find_extend_vma, struct vm_area_struct *, struct mm_struct * mm, unsigned long addr);
DECLARE_MOD_FUNC_DEP(handle_mm_fault, int, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, int write_access);
DECLARE_MOD_FUNC_DEP(get_gate_vma, struct vm_area_struct *, struct task_struct *tsk);
DECLARE_MOD_FUNC_DEP(in_gate_area_no_task, int, unsigned long addr);
DECLARE_MOD_FUNC_DEP(follow_page, struct page *, struct vm_area_struct * vma, unsigned long address, unsigned int foll_flags);
DECLARE_MOD_FUNC_DEP(__flush_anon_page, void, struct vm_area_struct *vma, struct page *page, unsigned long vmaddr);
DECLARE_MOD_FUNC_DEP(vm_normal_page, struct page *, struct vm_area_struct *vma, unsigned long addr, pte_t pte);
DECLARE_MOD_FUNC_DEP(flush_ptrace_access, void, struct vm_area_struct *vma, struct page *page, unsigned long uaddr, void *kaddr, unsigned long len, int write);


// deps controled by config macros
#ifdef KERNEL_HAS_ISPAGEPRESENT
DECLARE_MOD_FUNC_DEP(is_page_present, int, struct mm_struct * mm, unsigned long address);
#endif
#if defined(CONFIG_PREEMPT) && defined(CONFIG_PM)
DECLARE_MOD_FUNC_DEP(freeze_processes, int, void);
DECLARE_MOD_FUNC_DEP(thaw_processes, void, void);
#endif
// deps controled by arch type
#if defined(CONFIG_MIPS)
DECLARE_MOD_CB_DEP(flush_icache_range, void, unsigned long __user start, unsigned long __user end);
DECLARE_MOD_CB_DEP(flush_icache_page, void, struct vm_area_struct * vma, struct page * page);
DECLARE_MOD_CB_DEP(flush_cache_page, void, struct vm_area_struct * vma, unsigned long page);
#elif defined(CONFIG_X86)
DECLARE_MOD_FUNC_DEP(module_alloc, void *, unsigned long size);
DECLARE_MOD_FUNC_DEP(module_free, void, struct module *mod, void *module_region);
DECLARE_MOD_FUNC_DEP(fixup_exception, int, struct pt_regs * regs);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26))
DECLARE_MOD_FUNC_DEP(text_poke, void, void *addr, unsigned char *opcode, int len);
#else
DECLARE_MOD_FUNC_DEP(text_poke, void *, void *addr, const void *opcode, size_t len);
#endif
DECLARE_MOD_FUNC_DEP(show_registers, void, struct pt_regs * regs);
#elif defined(CONFIG_ARM)
#if defined(CONFIG_CPU_CACHE_VIPT) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18))
//DECLARE_MOD_FUNC_DEP(flush_ptrace_access, void, struct vm_area_struct * vma, struct page * page, unsigned long uaddr, void *kaddr, unsigned long len, int write);
#endif
#endif
// deps controled by kernel version
#if (LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 16))
DECLARE_MOD_FUNC_DEP(put_task_struct, void, struct task_struct *tsk);
#else //2.6.16
DECLARE_MOD_FUNC_DEP(put_task_struct, void, struct rcu_head * rhp);
#endif

//----------------- Implementation of module dependencies wrappers -----------------//
#define DECLARE_MOD_DEP_WRAPPER(name, ret, ...) ret name(__VA_ARGS__)
#define IMP_MOD_DEP_WRAPPER(name, ...) \
{ \
	return __ref_##name(__VA_ARGS__); \
}
/*#define IMP_MOD_DEP_WRAPPER_NORET(name, ...) \
{ \
	return __ref_##name(__VA_ARGS__); \
}*/
// persistent deps
DECLARE_MOD_DEP_WRAPPER(access_process_vm, int, struct task_struct *tsk, unsigned long addr, void *buf, int len, int write)
IMP_MOD_DEP_WRAPPER(access_process_vm, tsk, addr, buf, len, write)

DECLARE_MOD_DEP_WRAPPER (find_extend_vma, struct vm_area_struct *, struct mm_struct * mm, unsigned long addr)
IMP_MOD_DEP_WRAPPER (find_extend_vma, mm, addr)

DECLARE_MOD_DEP_WRAPPER (handle_mm_fault, int, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, int write_access)
IMP_MOD_DEP_WRAPPER (handle_mm_fault, mm, vma, address, write_access)

DECLARE_MOD_DEP_WRAPPER (get_gate_vma, struct vm_area_struct *, struct task_struct *tsk)
IMP_MOD_DEP_WRAPPER (get_gate_vma, tsk)

DECLARE_MOD_DEP_WRAPPER (in_gate_area_no_task, int, unsigned long addr)
IMP_MOD_DEP_WRAPPER (in_gate_area_no_task, addr)

DECLARE_MOD_DEP_WRAPPER (follow_page, struct page *, struct vm_area_struct * vma, unsigned long address, unsigned int foll_flags)
IMP_MOD_DEP_WRAPPER (follow_page, vma, address, foll_flags)

DECLARE_MOD_DEP_WRAPPER (__flush_anon_page, void, struct vm_area_struct *vma, struct page *page, unsigned long vmaddr)
IMP_MOD_DEP_WRAPPER (__flush_anon_page, vma, page, vmaddr)

DECLARE_MOD_DEP_WRAPPER(vm_normal_page, struct page *, struct vm_area_struct *vma, unsigned long addr, pte_t pte)
IMP_MOD_DEP_WRAPPER (vm_normal_page, vma, addr, pte)

DECLARE_MOD_DEP_WRAPPER (flush_ptrace_access, void, struct vm_area_struct *vma, struct page *page, unsigned long uaddr, void *kaddr, unsigned long len, int write)
IMP_MOD_DEP_WRAPPER (flush_ptrace_access, vma, page, uaddr, kaddr, len, write)


// deps controled by config macros
#ifdef KERNEL_HAS_ISPAGEPRESENT
int is_page_present (struct mm_struct *mm, unsigned long address)
{
	int ret; 
	  
	spin_lock (&(mm->page_table_lock)); 
	ret = __ref_is_page_present (mm, address); 
	spin_unlock (&(mm->page_table_lock)); 
	return ret;
}
#endif

#if defined(CONFIG_PREEMPT) && defined(CONFIG_PM)
DECLARE_MOD_DEP_WRAPPER(freeze_processes, int, void)
IMP_MOD_DEP_WRAPPER(freeze_processes)
DECLARE_MOD_DEP_WRAPPER(thaw_processes, void, void)
IMP_MOD_DEP_WRAPPER(thaw_processes)
#endif

// deps controled by arch type
#if defined(CONFIG_MIPS)
#elif defined(CONFIG_X86)
DECLARE_MOD_DEP_WRAPPER(module_alloc, void *, unsigned long size)
IMP_MOD_DEP_WRAPPER(module_alloc, size)
DECLARE_MOD_DEP_WRAPPER(module_free, void, struct module *mod, void *module_region)
IMP_MOD_DEP_WRAPPER(module_free, mod, module_region)
DECLARE_MOD_DEP_WRAPPER(fixup_exception, int, struct pt_regs * regs)
IMP_MOD_DEP_WRAPPER(fixup_exception, regs)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26))
DECLARE_MOD_DEP_WRAPPER(text_poke, void, void *addr, unsigned char *opcode, int len)
#else
DECLARE_MOD_DEP_WRAPPER(text_poke, void *, void *addr, const void *opcode, size_t len)
#endif
IMP_MOD_DEP_WRAPPER(text_poke, addr, opcode, len)
DECLARE_MOD_DEP_WRAPPER(show_registers, void, struct pt_regs * regs)
IMP_MOD_DEP_WRAPPER(show_registers, regs)
#elif defined(CONFIG_ARM)
#endif
// deps controled by kernel version
#if (LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 16))
//DECLARE_MOD_FUNC_DEP(put_task_struct, void, struct task_struct *tsk);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 11))
DECLARE_MOD_DEP_WRAPPER(put_task_struct, void, struct task_struct *tsk)
IMP_MOD_DEP_WRAPPER(put_task_struct, tsk)
#else // >= 2.6.11 and != 2.6.16.x
DECLARE_MOD_DEP_WRAPPER(__put_task_struct, void, struct task_struct *tsk)
IMP_MOD_DEP_WRAPPER(put_task_struct, tsk)
#endif
#else //2.6.16
DECLARE_MOD_DEP_WRAPPER(__put_task_struct_cb, void, struct rcu_head *rhp)
IMP_MOD_DEP_WRAPPER(put_task_struct, rhp)
#endif

//---------------------- Module dependencies initialization --------------------//
#define INIT_MOD_DEP_VAR(dep, name) \
{ \
	__ref_##dep = (void *) kallsyms_search (#name); \
	if (!__ref_##dep) \
	{ \
		  DBPRINTF (#name " is not found! Oops. Where is it?"); \
		  return -ESRCH; \
	} \
}

#define INIT_MOD_DEP_CB(dep, name) \
{ \
	dep = (void *) kallsyms_search (#name); \
	if (!dep) \
	{ \
		  DBPRINTF (#name " is not found! Oops. Where is it?"); \
		  return -ESRCH; \
	} \
}

int __init arch_init_kprobes (void)
{
#if !defined(CONFIG_X86)
	unsigned int xDoBp; unsigned int xKProbeHandler;
#endif
#if defined(CONFIG_MIPS)
	unsigned int xRegHi; unsigned int xRegLo;
#endif // ARCH
	int ret = 0;
	
	// Prepare to lookup names
	kallsyms_search = (void *) ksyms; 
	DBPRINTF ("kallsyms=0x%08x\n", ksyms);
 
	sched_addr = (kprobe_opcode_t *)kallsyms_search("__switch_to");//"schedule");
	fork_addr = (kprobe_opcode_t *)kallsyms_search("do_fork");

	INIT_MOD_DEP_VAR(handle_mm_fault, handle_mm_fault);
	INIT_MOD_DEP_VAR(flush_ptrace_access, flush_ptrace_access);
	INIT_MOD_DEP_VAR(find_extend_vma, find_extend_vma);
	INIT_MOD_DEP_VAR(get_gate_vma, get_gate_vma);
	INIT_MOD_DEP_VAR(in_gate_area_no_task, in_gate_area_no_task);
	INIT_MOD_DEP_VAR(follow_page, follow_page);
	INIT_MOD_DEP_VAR(__flush_anon_page, __flush_anon_page);
	INIT_MOD_DEP_VAR(vm_normal_page, vm_normal_page);
 
	INIT_MOD_DEP_VAR(access_process_vm, access_process_vm);
#ifdef KERNEL_HAS_ISPAGEPRESENT
	INIT_MOD_DEP_VAR(is_page_present, is_page_present);
#endif
#if (LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 16))
# if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 11))
	INIT_MOD_DEP_VAR(put_task_struct, put_task_struct);
# else
	INIT_MOD_DEP_VAR(put_task_struct, __put_task_struct);
# endif
#else /*2.6.16 */
	INIT_MOD_DEP_VAR(put_task_struct, __put_task_struct_cb);
#endif
#if defined(CONFIG_MIPS)
	INIT_MOD_DEP_CB(flush_icache_range, r4k_flush_icache_range);
	INIT_MOD_DEP_CB(flush_icache_page, r4k_flush_icache_page);
	INIT_MOD_DEP_CB(flush_cache_page, r4k_flush_cache_page);
#elif defined(CONFIG_X86)
	INIT_MOD_DEP_VAR(module_alloc, module_alloc);
	INIT_MOD_DEP_VAR(module_free, module_free);
	INIT_MOD_DEP_VAR(fixup_exception, fixup_exception);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)
# error this kernel version has no text_poke function which is necessaryf for x86 ach!!!
#else
	INIT_MOD_DEP_VAR(text_poke, text_poke);
#endif
	INIT_MOD_DEP_VAR(show_registers, show_registers);
#if defined(CONFIG_PREEMPT) && defined(CONFIG_PM)
	INIT_MOD_DEP_VAR(freeze_processes, freeze_processes);
	INIT_MOD_DEP_VAR(thaw_processes, thaw_processes);
#endif
	return ret;
#endif // CONFIG_X86	
	
#if !defined(CONFIG_X86)
	// Get instruction addresses
# if defined(CONFIG_MIPS)
	xDoBp = (unsigned int) kallsyms_search ("do_bp");
# elif defined(CONFIG_ARM)
	xDoBp = (unsigned int) kallsyms_search ("do_undefinstr");
# endif	// ARCH
	xKProbeHandler = (unsigned int) &kprobe_handler;
	gl_nNumberOfInstructions = sizeof (arrTrapsTemplate) / sizeof (arrTrapsTemplate[0]);
	gl_nCodeSize = gl_nNumberOfInstructions * sizeof (unsigned int); 
	DBPRINTF ("nNumberOfInstructions = %d\n", gl_nNumberOfInstructions);
	// Save original code
	arrTrapsOriginal = kmalloc (gl_nCodeSize /* + sizeof(unsigned int) */ , GFP_KERNEL);
	if (!arrTrapsOriginal)
	{
		DBPRINTF ("Unable to allocate space for original code of <do_bp>!\n"); 
		return -1;
	}
	memcpy (arrTrapsOriginal, (void *) xDoBp, gl_nCodeSize);
	// Fill in template
#if defined(CONFIG_MIPS)
	xRegHi = HIWORD (xKProbeHandler);
	xRegLo = LOWORD (xKProbeHandler); 
	if (xRegLo >= 0x8000) 
	xRegHi += 0x0001; 
	arrTrapsTemplate[REG_HI_INDEX] |= xRegHi; 
	arrTrapsTemplate[REG_LO_INDEX] |= xRegLo;
#elif defined(CONFIG_ARM)
	arrTrapsTemplate[NOTIFIER_CALL_CHAIN_INDEX] = arch_construct_brunch (xKProbeHandler, xDoBp + NOTIFIER_CALL_CHAIN_INDEX * 4, 1);
	//arrTrapsTemplate[NOTIFIER_CALL_CHAIN_INDEX1] = arch_construct_brunch(xKProbeHandler,
	//      xDoBp + NOTIFIER_CALL_CHAIN_INDEX1 * 4, 1);
	//arrTrapsTemplate[NOTIFIER_CALL_CHAIN_INDEX2] = arch_construct_brunch((unsigned int)arrTrapsOriginal,
	//      xDoBp + NOTIFIER_CALL_CHAIN_INDEX2 * 4, 1);
	//arrTrapsOriginal[gl_nNumberOfInstructions] = arch_construct_brunch(xDoBp + gl_nNumberOfInstructions * 4, 
	//      (unsigned int)(arrTrapsOriginal + gl_nNumberOfInstructions), 1);        
#endif // ARCH
	/*for(i = 0; i < gl_nNumberOfInstructions+1; i++)
	{
	printk("%08x\n", arrTrapsOriginal[i]);
	} */
	/*do_exit_p.kp.addr = (kprobe_opcode_t *)kallsyms_search ("do_exit");
	if (!do_exit_p.kp.addr)
	{
		DBPRINTF ("do_exit is not found! Oops. Where is it?");
		return -ESRCH;
	}
	if((ret = register_jprobe (&do_exit_p, 0)) != 0)
		return ret;*/

	// Insert new code
	memcpy ((void *) xDoBp, arrTrapsTemplate, gl_nCodeSize); 
	flush_icache_range (xDoBp, xDoBp + gl_nCodeSize); 
	if((ret = register_kprobe (&trampoline_p, 0)) != 0){
		//unregister_jprobe(&do_exit_p, 0);
		return ret;
	}
	
	return ret;	
#endif
}

void __exit arch_exit_kprobes (void)
{
#if !defined(CONFIG_X86)
	unsigned int xDoBp;
	// Get instruction address
#if defined(CONFIG_MIPS)
	xDoBp = (unsigned int) kallsyms_search ("do_bp");
#elif defined(CONFIG_ARM)
	xDoBp = (unsigned int) kallsyms_search ("do_undefinstr");
#endif // ARCH
	//unregister_jprobe(&do_exit_p, 0);
	// Replace back the original code
	memcpy ((void *) xDoBp, arrTrapsOriginal, gl_nCodeSize); 
	flush_icache_range (xDoBp, xDoBp + gl_nCodeSize); 
	kfree (arrTrapsOriginal); 
	arrTrapsOriginal = NULL;
#endif
}

MODULE_LICENSE ("Dual BSD/GPL");
