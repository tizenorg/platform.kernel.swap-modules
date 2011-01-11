#ifndef _DBI_ASM_ARM_KPROBES_H
#define _DBI_ASM_ARM_KPROBES_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/arch/asm-arm/dbi_kprobes.h
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
 * 2006-2007    Ekaterina Gorelkina <e.gorelkina@samsung.com>: initial implementation for ARM/MIPS
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts 
 *

 */

#include "../dbi_kprobes.h"
#include "dbi_kprobes_arm.h"
#include "dbi_kprobes_thumb.h"

typedef unsigned long kprobe_opcode_t;

#ifdef CONFIG_CPU_S3C2443
#define BREAKPOINT_INSTRUCTION          0xe1200070
#else 
#define BREAKPOINT_INSTRUCTION          0xffffffff
#endif /* CONFIG_CPU_S3C2443 */

#ifndef KPROBES_RET_PROBE_TRAMP

#ifdef CONFIG_CPU_S3C2443
#define UNDEF_INSTRUCTION               0xe1200071
#else 
#define UNDEF_INSTRUCTION               0xfffffffe
#endif /* CONFIG_CPU_S3C2443 */

#endif /* KPROBES_RET_PROBE_TRAMP */

#define MAX_INSN_SIZE                   1

# define UPROBES_TRAMP_LEN              8
# define UPROBES_TRAMP_INSN_IDX         2
# define UPROBES_TRAMP_SS_BREAK_IDX     4
# define UPROBES_TRAMP_RET_BREAK_IDX    5
# define KPROBES_TRAMP_LEN              8
# define KPROBES_TRAMP_INSN_IDX         UPROBES_TRAMP_INSN_IDX
# define KPROBES_TRAMP_SS_BREAK_IDX     UPROBES_TRAMP_SS_BREAK_IDX
# define KPROBES_TRAMP_RET_BREAK_IDX	UPROBES_TRAMP_RET_BREAK_IDX

#define NOTIFIER_CALL_CHAIN_INDEX       3

// undefined
# define MASK_ARM_INSN_UNDEF		0x0FF00000
# define PTRN_ARM_INSN_UNDEF		0x03000000
// architecturally undefined
# define MASK_ARM_INSN_AUNDEF           0x0FF000F0
# define PTRN_ARM_INSN_AUNDEF           0x07F000F0
// branches
# define MASK_ARM_INSN_B		0x0E000000
# define PTRN_ARM_INSN_B		0x0A000000
# define MASK_ARM_INSN_BL		0x0E000000
# define PTRN_ARM_INSN_BL		0x0B000000
# define MASK_ARM_INSN_BLX1		0xFF000000
# define PTRN_ARM_INSN_BLX1		0xFA000000
# define MASK_ARM_INSN_BLX2		0x0FF000F0
# define PTRN_ARM_INSN_BLX2		0x01200030
# define MASK_ARM_INSN_BX		0x0FF000F0
# define PTRN_ARM_INSN_BX		0x01200010
# define MASK_ARM_INSN_BXJ		0x0FF000F0
# define PTRN_ARM_INSN_BXJ		0x01200020
// software interrupts
# define MASK_ARM_INSN_SWI		0x0F000000
# define PTRN_ARM_INSN_SWI		0x0F000000
// break
# define MASK_ARM_INSN_BREAK		0xFFF000F0
# define PTRN_ARM_INSN_BREAK		0xE1200070
// Data processing immediate shift
# define MASK_ARM_INSN_DPIS		0x0E000010
# define PTRN_ARM_INSN_DPIS		0x00000000
// Data processing register shift
# define MASK_ARM_INSN_DPRS		0x0E000090
# define PTRN_ARM_INSN_DPRS		0x00000010
// Data processing immediate
# define MASK_ARM_INSN_DPI		0x0E000000
# define PTRN_ARM_INSN_DPI		0x02000000
// Load immediate offset
# define MASK_ARM_INSN_LIO		0x0E100000
# define PTRN_ARM_INSN_LIO		0x04100000
// Store immediate offset
# define MASK_ARM_INSN_SIO		MASK_ARM_INSN_LIO
# define PTRN_ARM_INSN_SIO		0x04000000
// Load register offset
# define MASK_ARM_INSN_LRO		0x0E100010
# define PTRN_ARM_INSN_LRO		0x06100000
// Store register offset
# define MASK_ARM_INSN_SRO		MASK_ARM_INSN_LRO
# define PTRN_ARM_INSN_SRO		0x06000000
// Load multiple
# define MASK_ARM_INSN_LM		0x0E100000
# define PTRN_ARM_INSN_LM		0x08100000
// Store multiple
# define MASK_ARM_INSN_SM		MASK_ARM_INSN_LM
# define PTRN_ARM_INSN_SM		0x08000000
// Coprocessor load/store and double register transfers
# define MASK_ARM_INSN_CLS		0x0E000000
# define PTRN_ARM_INSN_CLS		0x0C000000
// Coprocessor register transfers
# define MASK_ARM_INSN_CRT		0x0F000010
# define PTRN_ARM_INSN_CRT		0x0E000010

# define ARM_INSN_MATCH(name, insn)	        ((insn & MASK_ARM_INSN_##name) == PTRN_ARM_INSN_##name)
# define ARM_INSN_REG_RN(insn)                   ((insn & 0x000F0000)>>16)
# define ARM_INSN_REG_SET_RN(insn, nreg)	        {insn &= ~0x000F0000; insn |= nreg<<16;}
# define ARM_INSN_REG_RD(insn)		        ((insn & 0x0000F000)>>12)
# define ARM_INSN_REG_SET_RD(insn, nreg)	        {insn &= ~0x0000F000; insn |= nreg<<12;}
# define ARM_INSN_REG_RS(insn)		        ((insn & 0x00000F00)>>8)
# define ARM_INSN_REG_SET_RS(insn, nreg)	        {insn &= ~0x00000F00; insn |= nreg<<8;}
# define ARM_INSN_REG_RM(insn)		        (insn & 0x0000000F)
# define ARM_INSN_REG_SET_RM(insn, nreg)	        {insn &= ~0x0000000F; insn |= nreg;}
# define ARM_INSN_REG_MR(insn, nreg)	        (insn & (1 << nreg))
# define ARM_INSN_REG_SET_MR(insn, nreg)         {insn |= (1 << nreg);}
# define ARM_INSN_REG_CLEAR_MR(insn, nreg)	{insn &= ~(1 << nreg);}

/* per-cpu kprobe control block */
struct kprobe_ctlblk {
	unsigned long kprobe_status;
	struct prev_kprobe prev_kprobe;
};

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

typedef kprobe_opcode_t (*entry_point_t) (unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

//void gen_insn_execbuf (void);
//void pc_dep_insn_execbuf (void);
//void gen_insn_execbuf_holder (void);
//void pc_dep_insn_execbuf_holder (void);

void patch_suspended_task_ret_addr(struct task_struct *p, struct kretprobe *rp);


#endif /* _DBI_ASM_ARM_KPROBES_H */
