#ifndef _SRC_ASM_MIPS_KPROBES_H
#define _SRC_ASM_MIPS_KPROBES_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/arch/asm-mips/dbi_kprobes.h
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
 * 2006-2007    Ekaterina Gorelkina <e.gorelkina@samsung.com>:
 *		initial implementation for ARM/MIPS
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both
 *		user-space and kernel space.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>:
 *		redesign module for separating core and arch parts
 *
 */

#include <kprobe/dbi_kprobes_deps.h>
#include <kprobe/dbi_kprobes.h>

typedef unsigned long kprobe_opcode_t;

#define BREAKPOINT_INSTRUCTION         0x0000000d

#ifndef KPROBES_RET_PROBE_TRAMP
#define UNDEF_INSTRUCTION              0x0000004d
#endif

#define MAX_INSN_SIZE                  1

# define UPROBES_TRAMP_LEN             3
# define UPROBES_TRAMP_INSN_IDX        0
# define UPROBES_TRAMP_SS_BREAK_IDX    1
# define UPROBES_TRAMP_RET_BREAK_IDX   2
# define KPROBES_TRAMP_LEN             UPROBES_TRAMP_LEN
# define KPROBES_TRAMP_INSN_IDX        UPROBES_TRAMP_INSN_IDX
# define KPROBES_TRAMP_SS_BREAK_IDX    UPROBES_TRAMP_SS_BREAK_IDX
# define KPROBES_TRAMP_RET_BREAK_IDX   UPROBES_TRAMP_RET_BREAK_IDX

#define REG_HI_INDEX                   0
#define REG_LO_INDEX                   1
#define NOTIFIER_CALL_CHAIN_INDEX      0


#define MIPS_INSN_OPCODE_MASK	0xFC000000
#define MIPS_INSN_RS_MASK	0x03E00000
#define MIPS_INSN_RT_MASK	0x001F0000
/* #define MIPS_INSN_UN_MASK     0x0000FFC0 */
#define MIPS_INSN_FUNC_MASK     0x0000003F
#define MIPS_INSN_OPCODE(insn)	(insn & MIPS_INSN_OPCODE_MASK)
#define MIPS_INSN_RS(insn)      (insn & MIPS_INSN_RS_MASK)
#define MIPS_INSN_RT(insn)      (insn & MIPS_INSN_RT_MASK)
#define MIPS_INSN_FUNC(insn)	(insn & MIPS_INSN_FUNC_MASK)
/* opcodes 31..26 */
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
/*  rs 25..21 */
#define MIPS_BC_RS		0x01000000
/*  rt 20..16 */
#define MIPS_BLTZ_RT		0x00000000
#define MIPS_BGEZ_RT		0x00010000
#define MIPS_BLTZL_RT		0x00020000
#define MIPS_BGEZL_RT		0x00030000
#define MIPS_BLTZAL_RT		0x00100000
#define MIPS_BGEZAL_RT		0x00110000
#define MIPS_BLTZALL_RT		0x00120000
#define MIPS_BGEZALL_RT		0x00130000
/*  unnamed 15..6 */
/*  function 5..0 */
#define MIPS_JR_FUNC		0x00000008
#define MIPS_JALR_FUNC		0x00000009
#define MIPS_BREAK_FUNC		0x0000000D
#define MIPS_SYSCALL_FUNC	0x0000000C


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

typedef kprobe_opcode_t (*entry_point_t) (unsigned long, unsigned long,
					  unsigned long, unsigned long,
					  unsigned long, unsigned long);


void gen_insn_execbuf_holder(void);

void patch_suspended_task_ret_addr(struct task_struct *p, struct kretprobe *rp);
int arch_init_module_deps(void);

#endif /*  _SRC_ASM_MIPS_KPROBES_H */
