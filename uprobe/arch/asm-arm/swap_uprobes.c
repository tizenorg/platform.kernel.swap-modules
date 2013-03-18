#include <dbi_kprobes.h>
#include <asm/dbi_kprobes.h>
#include <asm/traps.h>
#include <swap_uprobes.h>

// FIXME:
#include <dbi_kdebug.h>
extern struct hlist_head uprobe_insn_pages;
kprobe_opcode_t *get_insn_slot(struct task_struct *task, struct hlist_head *page_list, int atomic);
int arch_check_insn_arm(struct arch_specific_insn *ainsn);
int prep_pc_dep_insn_execbuf(kprobe_opcode_t *insns, kprobe_opcode_t insn, int uregs);
void free_insn_slot(struct hlist_head *page_list, struct task_struct *task, kprobe_opcode_t *slot);
void pc_dep_insn_execbuf(void);
void gen_insn_execbuf(void);
void gen_insn_execbuf_thumb(void);
void pc_dep_insn_execbuf_thumb(void);
int kprobe_trap_handler(struct pt_regs *regs, unsigned int instr);


#define sign_extend(x, signbit) ((x) | (0 - ((x) & (1 << (signbit)))))
#define branch_displacement(insn) sign_extend(((insn) & 0xffffff) << 2, 25)

static kprobe_opcode_t get_addr_b(kprobe_opcode_t insn, kprobe_opcode_t *addr)
{
	// real position less then PC by 8
	return (kprobe_opcode_t)((long)addr + 8 + branch_displacement(insn));
}

/* is instruction Thumb2 and NOT a branch, etc... */
static int is_thumb2(kprobe_opcode_t insn)
{
	return ((insn & 0xf800) == 0xe800 ||
		(insn & 0xf800) == 0xf000 ||
		(insn & 0xf800) == 0xf800);
}

static int arch_copy_trampoline_arm_uprobe(struct kprobe *p, struct task_struct *task, int atomic)
{
	kprobe_opcode_t insns[UPROBES_TRAMP_LEN];
	int uregs, pc_dep;
	kprobe_opcode_t insn[MAX_INSN_SIZE];
	struct arch_specific_insn ainsn;

	p->safe_arm = -1;
	if ((unsigned long)p->addr & 0x01) {
		printk("Error in %s at %d: attempt to register kprobe at an unaligned address\n", __FILE__, __LINE__);
		return -EINVAL;
	}

	insn[0] = p->opcode;
	ainsn.insn_arm = insn;
	if (!arch_check_insn_arm(&ainsn)) {
		p->safe_arm = 0;
	}

	uregs = pc_dep = 0;
	// Rn, Rm ,Rd
	if (ARM_INSN_MATCH(DPIS, insn[0]) || ARM_INSN_MATCH(LRO, insn[0]) ||
	    ARM_INSN_MATCH(SRO, insn[0])) {
		uregs = 0xb;
		if ((ARM_INSN_REG_RN(insn[0]) == 15) || (ARM_INSN_REG_RM(insn[0]) == 15) ||
		    (ARM_INSN_MATCH(SRO, insn[0]) && (ARM_INSN_REG_RD(insn[0]) == 15))) {
			DBPRINTF("Unboostable insn %lx, DPIS/LRO/SRO\n", insn[0]);
			pc_dep = 1;
		}

	// Rn ,Rd
	} else if (ARM_INSN_MATCH(DPI, insn[0]) || ARM_INSN_MATCH(LIO, insn[0]) ||
		   ARM_INSN_MATCH (SIO, insn[0])) {
		uregs = 0x3;
		if ((ARM_INSN_REG_RN(insn[0]) == 15) || (ARM_INSN_MATCH(SIO, insn[0]) &&
		    (ARM_INSN_REG_RD(insn[0]) == 15))) {
			pc_dep = 1;
			DBPRINTF("Unboostable insn %lx/%p, DPI/LIO/SIO\n", insn[0], p);
		}

	// Rn, Rm, Rs
	} else if (ARM_INSN_MATCH(DPRS, insn[0])) {
		uregs = 0xd;
		if ((ARM_INSN_REG_RN(insn[0]) == 15) || (ARM_INSN_REG_RM(insn[0]) == 15) ||
		    (ARM_INSN_REG_RS(insn[0]) == 15)) {
			pc_dep = 1;
			DBPRINTF("Unboostable insn %lx, DPRS\n", insn[0]);
		}

	// register list
	} else if (ARM_INSN_MATCH(SM, insn[0])) {
		uregs = 0x10;
		if (ARM_INSN_REG_MR (insn[0], 15))
		{
			DBPRINTF ("Unboostable insn %lx, SM\n", insn[0]);
			pc_dep = 1;
		}
	}

	// check instructions that can write result to SP andu uses PC
	if (pc_dep  && (ARM_INSN_REG_RD (ainsn.insn_arm[0]) == 13)) {
		printk("Error in %s at %d: instruction check failed (arm)\n", __FILE__, __LINE__);
		p->safe_arm = -1;
		// TODO: move free to later phase
		//free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn_arm, 0);
		//ret = -EFAULT;
	}

	if (unlikely(uregs && pc_dep)) {
		memcpy(insns, pc_dep_insn_execbuf, sizeof(insns));
		if (prep_pc_dep_insn_execbuf(insns, insn[0], uregs) != 0) {
			printk("Error in %s at %d: failed to prepare exec buffer for insn %lx!",
			       __FILE__, __LINE__, insn[0]);
			p->safe_arm = -1;
			// TODO: move free to later phase
			//free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn_arm, 0);
			//return -EINVAL;
		}

		insns[6] = (kprobe_opcode_t) (p->addr + 2);
	} else {
		memcpy(insns, gen_insn_execbuf, sizeof(insns));
		insns[UPROBES_TRAMP_INSN_IDX] = insn[0];
	}

	insns[UPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
	insns[7] = (kprobe_opcode_t) (p->addr + 1);

	// B
	if(ARM_INSN_MATCH(B, ainsn.insn_arm[0])) {
		memcpy(insns, pc_dep_insn_execbuf, sizeof(insns));
		insns[UPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
		insns[6] = (kprobe_opcode_t)(p->addr + 2);
		insns[7] = get_addr_b(p->opcode, p->addr);
	}

	DBPRINTF("arch_prepare_uprobe: to %p - %lx %lx %lx %lx %lx %lx %lx %lx %lx",
		 p->ainsn.insn_arm, insns[0], insns[1], insns[2], insns[3], insns[4],
		 insns[5], insns[6], insns[7], insns[8]);
	if (!write_proc_vm_atomic(task, (unsigned long)p->ainsn.insn_arm, insns, sizeof(insns))) {
		panic("failed to write memory %p!\n", p->ainsn.insn_arm);
		// Mr_Nobody: we have to panic, really??...
		//free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn_arm, 0);
		//return -EINVAL;
	}

	return 0;
}

static int arch_check_insn_thumb(struct arch_specific_insn *ainsn)
{
	int ret = 0;

	// check instructions that can change PC
	if (THUMB_INSN_MATCH(UNDEF, ainsn->insn_thumb[0]) ||
	    THUMB_INSN_MATCH(SWI, ainsn->insn_thumb[0]) ||
	    THUMB_INSN_MATCH(BREAK, ainsn->insn_thumb[0]) ||
	    THUMB2_INSN_MATCH(BL, ainsn->insn_thumb[0]) ||
	    THUMB_INSN_MATCH(B1, ainsn->insn_thumb[0]) ||
	    THUMB_INSN_MATCH(B2, ainsn->insn_thumb[0]) ||
	    THUMB_INSN_MATCH(CBZ, ainsn->insn_thumb[0]) ||
	    THUMB2_INSN_MATCH(B1, ainsn->insn_thumb[0]) ||
	    THUMB2_INSN_MATCH(B2, ainsn->insn_thumb[0]) ||
	    THUMB2_INSN_MATCH(BLX1, ainsn->insn_thumb[0]) ||
	    THUMB_INSN_MATCH(BLX2, ainsn->insn_thumb[0]) ||
	    THUMB_INSN_MATCH(BX, ainsn->insn_thumb[0]) ||
	    THUMB2_INSN_MATCH(BXJ, ainsn->insn_thumb[0]) ||
	    (THUMB2_INSN_MATCH(ADR, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LDRW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RT(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LDRW1, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RT(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LDRHW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RT(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LDRHW1, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RT(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LDRWL, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RT(ainsn->insn_thumb[0]) == 15) ||
	    THUMB2_INSN_MATCH(LDMIA, ainsn->insn_thumb[0]) ||
	    THUMB2_INSN_MATCH(LDMDB, ainsn->insn_thumb[0]) ||
	    (THUMB2_INSN_MATCH(DP, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(RSBW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(RORW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(ROR, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LSLW1, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LSLW2, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LSRW1, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LSRW2, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RD(ainsn->insn_thumb[0]) == 15) ||
	    /* skip PC, #-imm12 -> SP, #-imm8 and Tegra-hanging instructions */
	    (THUMB2_INSN_MATCH(STRW1, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RN(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(STRBW1, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RN(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(STRHW1, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RN(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(STRW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RN(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(STRHW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RN(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LDRW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RN(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LDRBW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RN(ainsn->insn_thumb[0]) == 15) ||
	    (THUMB2_INSN_MATCH(LDRHW, ainsn->insn_thumb[0]) && THUMB2_INSN_REG_RN(ainsn->insn_thumb[0]) == 15) ||
	    /* skip STRDx/LDRDx Rt, Rt2, [Rd, ...] */
	    (THUMB2_INSN_MATCH(LDRD, ainsn->insn_thumb[0]) || THUMB2_INSN_MATCH(LDRD1, ainsn->insn_thumb[0]) || THUMB2_INSN_MATCH(STRD, ainsn->insn_thumb[0])) ) {
		DBPRINTF("Bad insn arch_check_insn_thumb: %lx\n", ainsn->insn_thumb[0]);
		ret = -EFAULT;
	}

	return ret;
}

static int prep_pc_dep_insn_execbuf_thumb(kprobe_opcode_t * insns, kprobe_opcode_t insn, int uregs)
{
	unsigned char mreg = 0;
	unsigned char reg = 0;

	if (THUMB_INSN_MATCH(APC, insn) || THUMB_INSN_MATCH(LRO3, insn)) {
		reg = ((insn & 0xffff) & uregs) >> 8;
	} else {
		if (THUMB_INSN_MATCH(MOV3, insn)) {
			if (((((unsigned char) insn) & 0xff) >> 3) == 15) {
				reg = (insn & 0xffff) & uregs;
			} else {
				return 0;
			}
		} else {
			if (THUMB2_INSN_MATCH(ADR, insn)) {
				reg = ((insn >> 16) & uregs) >> 8;
				if (reg == 15) {
					return 0;
				}
			} else {
				if (THUMB2_INSN_MATCH(LDRW, insn) || THUMB2_INSN_MATCH(LDRW1, insn) ||
				    THUMB2_INSN_MATCH(LDRHW, insn) || THUMB2_INSN_MATCH(LDRHW1, insn) ||
				    THUMB2_INSN_MATCH(LDRWL, insn)) {
					reg = ((insn >> 16) & uregs) >> 12;
					if (reg == 15) {
						return 0;
					}
				} else {
					// LDRB.W PC, [PC, #immed] => PLD [PC, #immed], so Rt == PC is skipped
					if (THUMB2_INSN_MATCH(LDRBW, insn) || THUMB2_INSN_MATCH(LDRBW1, insn) ||
					    THUMB2_INSN_MATCH(LDREX, insn)) {
						reg = ((insn >> 16) & uregs) >> 12;
					} else {
						if (THUMB2_INSN_MATCH(DP, insn)) {
							reg = ((insn >> 16) & uregs) >> 12;
							if (reg == 15) {
								return 0;
							}
						} else {
							if (THUMB2_INSN_MATCH(RSBW, insn)) {
								reg = ((insn >> 12) & uregs) >> 8;
								if (reg == 15){
									return 0;
								}
							} else {
								if (THUMB2_INSN_MATCH(RORW, insn)) {
									reg = ((insn >> 12) & uregs) >> 8;
									if (reg == 15) {
										return 0;
									}
								} else {
									if (THUMB2_INSN_MATCH(ROR, insn) || THUMB2_INSN_MATCH(LSLW1, insn) ||
									    THUMB2_INSN_MATCH(LSLW2, insn) || THUMB2_INSN_MATCH(LSRW1, insn) ||
									    THUMB2_INSN_MATCH(LSRW2, insn)) {
										reg = ((insn >> 12) & uregs) >> 8;
										if (reg == 15) {
											return 0;
										}
									} else {
										if (THUMB2_INSN_MATCH(TEQ1, insn) || THUMB2_INSN_MATCH(TST1, insn)) {
											reg = 15;
										} else {
											if (THUMB2_INSN_MATCH(TEQ2, insn) || THUMB2_INSN_MATCH(TST2, insn)) {
												reg = THUMB2_INSN_REG_RM(insn);
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if ((THUMB2_INSN_MATCH(STRW, insn) || THUMB2_INSN_MATCH(STRBW, insn) ||
	     THUMB2_INSN_MATCH(STRD, insn) || THUMB2_INSN_MATCH(STRHT, insn) ||
	     THUMB2_INSN_MATCH(STRT, insn) || THUMB2_INSN_MATCH(STRHW1, insn) ||
	     THUMB2_INSN_MATCH(STRHW, insn)) && THUMB2_INSN_REG_RT(insn) == 15) {
		reg = THUMB2_INSN_REG_RT(insn);
	}

	if (reg == 6 || reg == 7) {
		*((unsigned short*)insns + 0) = (*((unsigned short*)insns + 0) & 0x00ff) | ((1 << mreg) | (1 << (mreg + 1)));
		*((unsigned short*)insns + 1) = (*((unsigned short*)insns + 1) & 0xf8ff) | (mreg << 8);
		*((unsigned short*)insns + 2) = (*((unsigned short*)insns + 2) & 0xfff8) | (mreg + 1);
		*((unsigned short*)insns + 3) = (*((unsigned short*)insns + 3) & 0xffc7) | (mreg << 3);
		*((unsigned short*)insns + 7) = (*((unsigned short*)insns + 7) & 0xf8ff) | (mreg << 8);
		*((unsigned short*)insns + 8) = (*((unsigned short*)insns + 8) & 0xffc7) | (mreg << 3);
		*((unsigned short*)insns + 9) = (*((unsigned short*)insns + 9) & 0xffc7) | ((mreg + 1) << 3);
		*((unsigned short*)insns + 10) = (*((unsigned short*)insns + 10) & 0x00ff) | (( 1 << mreg) | (1 << (mreg + 1)));
	}

	if (THUMB_INSN_MATCH(APC, insn)) {
		// ADD Rd, PC, #immed_8*4 -> ADD Rd, SP, #immed_8*4
		*((unsigned short*)insns + 4) = ((insn & 0xffff) | 0x800);				// ADD Rd, SP, #immed_8*4
	} else {
		if (THUMB_INSN_MATCH(LRO3, insn)) {
			// LDR Rd, [PC, #immed_8*4] -> LDR Rd, [SP, #immed_8*4]
			*((unsigned short*)insns + 4) = ((insn & 0xffff) + 0x5000);			// LDR Rd, [SP, #immed_8*4]
		} else {
			if (THUMB_INSN_MATCH(MOV3, insn)) {
				// MOV Rd, PC -> MOV Rd, SP
				*((unsigned short*)insns + 4) = ((insn & 0xffff) ^ 0x10);		// MOV Rd, SP
			} else {
				if (THUMB2_INSN_MATCH(ADR, insn)) {
					// ADDW Rd, PC, #imm -> ADDW Rd, SP, #imm
					insns[2] = (insn & 0xfffffff0) | 0x0d;				// ADDW Rd, SP, #imm
				} else {
					if (THUMB2_INSN_MATCH(LDRW, insn) || THUMB2_INSN_MATCH(LDRBW, insn) ||
					    THUMB2_INSN_MATCH(LDRHW, insn)) {
						// LDR.W Rt, [PC, #-<imm_12>] -> LDR.W Rt, [SP, #-<imm_8>]
						// !!!!!!!!!!!!!!!!!!!!!!!!
						// !!! imm_12 vs. imm_8 !!!
						// !!!!!!!!!!!!!!!!!!!!!!!!
						insns[2] = (insn & 0xf0fffff0) | 0x0c00000d;		// LDR.W Rt, [SP, #-<imm_8>]
					} else {
						if (THUMB2_INSN_MATCH(LDRW1, insn) || THUMB2_INSN_MATCH(LDRBW1, insn) ||
						    THUMB2_INSN_MATCH(LDRHW1, insn) || THUMB2_INSN_MATCH(LDRD, insn) ||
						    THUMB2_INSN_MATCH(LDRD1, insn) || THUMB2_INSN_MATCH(LDREX, insn)) {
							// LDRx.W Rt, [PC, #+<imm_12>] -> LDRx.W Rt, [SP, #+<imm_12>] (+/-imm_8 for LDRD Rt, Rt2, [PC, #<imm_8>]
							insns[2] = (insn & 0xfffffff0) | 0xd;													// LDRx.W Rt, [SP, #+<imm_12>]
						} else {
							if (THUMB2_INSN_MATCH(MUL, insn)) {
								insns[2] = (insn & 0xfff0ffff) | 0x000d0000;											// MUL Rd, Rn, SP
							} else {
								if (THUMB2_INSN_MATCH(DP, insn)) {
									if (THUMB2_INSN_REG_RM(insn) == 15) {
										insns[2] = (insn & 0xfff0ffff) | 0x000d0000;									// DP Rd, Rn, PC
									} else if (THUMB2_INSN_REG_RN(insn) == 15) {
										insns[2] = (insn & 0xfffffff0) | 0xd;										// DP Rd, PC, Rm
									}
								} else {
									if (THUMB2_INSN_MATCH(LDRWL, insn)) {
										// LDRx.W Rt, [PC, #<imm_12>] -> LDRx.W Rt, [SP, #+<imm_12>] (+/-imm_8 for LDRD Rt, Rt2, [PC, #<imm_8>]
										insns[2] = (insn & 0xfffffff0) | 0xd;										// LDRx.W Rt, [SP, #+<imm_12>]
									} else {
										if (THUMB2_INSN_MATCH(RSBW, insn)) {
											insns[2] = (insn & 0xfffffff0) | 0xd;									// RSB{S}.W Rd, PC, #<const> -> RSB{S}.W Rd, SP, #<const>
										} else {
											if (THUMB2_INSN_MATCH(RORW, insn) || THUMB2_INSN_MATCH(LSLW1, insn) || THUMB2_INSN_MATCH(LSRW1, insn)) {
												if ((THUMB2_INSN_REG_RM(insn) == 15) && (THUMB2_INSN_REG_RN(insn) == 15)) {
													insns[2] = (insn & 0xfffdfffd);								// ROR.W Rd, PC, PC
												} else if (THUMB2_INSN_REG_RM(insn) == 15) {
													insns[2] = (insn & 0xfff0ffff) | 0xd0000;						// ROR.W Rd, Rn, PC
												} else if (THUMB2_INSN_REG_RN(insn) == 15) {
													insns[2] = (insn & 0xfffffff0) | 0xd;							// ROR.W Rd, PC, Rm
												}
											} else {
												if (THUMB2_INSN_MATCH(ROR, insn) || THUMB2_INSN_MATCH(LSLW2, insn) || THUMB2_INSN_MATCH(LSRW2, insn)) {
													insns[2] = (insn & 0xfff0ffff) | 0xd0000;						// ROR{S} Rd, PC, #<const> -> ROR{S} Rd, SP, #<const>
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (THUMB2_INSN_MATCH(STRW, insn) || THUMB2_INSN_MATCH(STRBW, insn)) {
		insns[2] = (insn & 0xfff0ffff) | 0x000d0000;								// STRx.W Rt, [Rn, SP]
	} else {
		if (THUMB2_INSN_MATCH(STRD, insn) || THUMB2_INSN_MATCH(STRHT, insn) ||
		    THUMB2_INSN_MATCH(STRT, insn) || THUMB2_INSN_MATCH(STRHW1, insn)) {
			if (THUMB2_INSN_REG_RN(insn) == 15) {
				insns[2] = (insn & 0xfffffff0) | 0xd;							// STRD/T/HT{.W} Rt, [SP, ...]
			} else {
				insns[2] = insn;
			}
		} else {
			if (THUMB2_INSN_MATCH(STRHW, insn) && (THUMB2_INSN_REG_RN(insn) == 15)) {
				if (THUMB2_INSN_REG_RN(insn) == 15) {
					insns[2] = (insn & 0xf0fffff0) | 0x0c00000d;					// STRH.W Rt, [SP, #-<imm_8>]
				} else {
					insns[2] = insn;
				}
			}
		}
	}

	// STRx PC, xxx
	if ((reg == 15) && (THUMB2_INSN_MATCH(STRW, insn)   ||
			    THUMB2_INSN_MATCH(STRBW, insn)  ||
			    THUMB2_INSN_MATCH(STRD, insn)   ||
			    THUMB2_INSN_MATCH(STRHT, insn)  ||
			    THUMB2_INSN_MATCH(STRT, insn)   ||
			    THUMB2_INSN_MATCH(STRHW1, insn) ||
			    THUMB2_INSN_MATCH(STRHW, insn) )) {
		insns[2] = (insns[2] & 0x0fffffff) | 0xd0000000;
	}

	if (THUMB2_INSN_MATCH(TEQ1, insn) || THUMB2_INSN_MATCH(TST1, insn)) {
		insns[2] = (insn & 0xfffffff0) | 0xd;									// TEQ SP, #<const>
	} else {
		if (THUMB2_INSN_MATCH(TEQ2, insn) || THUMB2_INSN_MATCH(TST2, insn)) {
			if ((THUMB2_INSN_REG_RN(insn) == 15) && (THUMB2_INSN_REG_RM(insn) == 15)) {
				insns[2] = (insn & 0xfffdfffd);								// TEQ/TST PC, PC
			} else if (THUMB2_INSN_REG_RM(insn) == 15) {
				insns[2] = (insn & 0xfff0ffff) | 0xd0000;						// TEQ/TST Rn, PC
			} else if (THUMB2_INSN_REG_RN(insn) == 15) {
				insns[2] = (insn & 0xfffffff0) | 0xd;							// TEQ/TST PC, Rm
			}
		}
	}

	return 0;
}

static int arch_copy_trampoline_thumb_uprobe(struct kprobe *p, struct task_struct *task, int atomic)
{
	int uregs, pc_dep;
	unsigned int addr;
	kprobe_opcode_t insn[MAX_INSN_SIZE];
	struct arch_specific_insn ainsn;
	kprobe_opcode_t insns[UPROBES_TRAMP_LEN * 2];

	p->safe_thumb = -1;
	if ((unsigned long)p->addr & 0x01) {
		printk("Error in %s at %d: attempt to register kprobe at an unaligned address\n", __FILE__, __LINE__);
		return -EINVAL;
	}

	insn[0] = p->opcode;
	ainsn.insn_thumb = insn;
	if (!arch_check_insn_thumb(&ainsn)) {
		p->safe_thumb = 0;
	}

	uregs = 0;
	pc_dep = 0;

	if (THUMB_INSN_MATCH(APC, insn[0]) || THUMB_INSN_MATCH(LRO3, insn[0])) {
		uregs = 0x0700;		// 8-10
		pc_dep = 1;
	} else if (THUMB_INSN_MATCH(MOV3, insn[0]) && (((((unsigned char)insn[0]) & 0xff) >> 3) == 15)) {
		// MOV Rd, PC
		uregs = 0x07;
		pc_dep = 1;
	} else if THUMB2_INSN_MATCH(ADR, insn[0]) {
		uregs = 0x0f00;		// Rd 8-11
		pc_dep = 1;
	} else if (((THUMB2_INSN_MATCH(LDRW, insn[0]) || THUMB2_INSN_MATCH(LDRW1, insn[0]) ||
		     THUMB2_INSN_MATCH(LDRBW, insn[0]) || THUMB2_INSN_MATCH(LDRBW1, insn[0]) ||
		     THUMB2_INSN_MATCH(LDRHW, insn[0]) || THUMB2_INSN_MATCH(LDRHW1, insn[0]) ||
		     THUMB2_INSN_MATCH(LDRWL, insn[0])) && THUMB2_INSN_REG_RN(insn[0]) == 15) ||
		     THUMB2_INSN_MATCH(LDREX, insn[0]) ||
		     ((THUMB2_INSN_MATCH(STRW, insn[0]) || THUMB2_INSN_MATCH(STRBW, insn[0]) ||
		       THUMB2_INSN_MATCH(STRHW, insn[0]) || THUMB2_INSN_MATCH(STRHW1, insn[0])) &&
		      (THUMB2_INSN_REG_RN(insn[0]) == 15 || THUMB2_INSN_REG_RT(insn[0]) == 15)) ||
		     ((THUMB2_INSN_MATCH(STRT, insn[0]) || THUMB2_INSN_MATCH(STRHT, insn[0])) &&
		       (THUMB2_INSN_REG_RN(insn[0]) == 15 || THUMB2_INSN_REG_RT(insn[0]) == 15))) {
		uregs = 0xf000;		// Rt 12-15
		pc_dep = 1;
	} else if ((THUMB2_INSN_MATCH(LDRD, insn[0]) || THUMB2_INSN_MATCH(LDRD1, insn[0])) && (THUMB2_INSN_REG_RN(insn[0]) == 15)) {
		uregs = 0xff00;		// Rt 12-15, Rt2 8-11
		pc_dep = 1;
	} else if (THUMB2_INSN_MATCH(MUL, insn[0]) && THUMB2_INSN_REG_RM(insn[0]) == 15) {
		uregs = 0xf;
		pc_dep = 1;
	} else if (THUMB2_INSN_MATCH(DP, insn[0]) && (THUMB2_INSN_REG_RN(insn[0]) == 15 || THUMB2_INSN_REG_RM(insn[0]) == 15)) {
		uregs = 0xf000;		// Rd 12-15
		pc_dep = 1;
	} else if (THUMB2_INSN_MATCH(STRD, insn[0]) && ((THUMB2_INSN_REG_RN(insn[0]) == 15) || (THUMB2_INSN_REG_RT(insn[0]) == 15) || THUMB2_INSN_REG_RT2(insn[0]) == 15)) {
		uregs = 0xff00;		// Rt 12-15, Rt2 8-11
		pc_dep = 1;
	} else if (THUMB2_INSN_MATCH(RSBW, insn[0]) && THUMB2_INSN_REG_RN(insn[0]) == 15) {
		uregs = 0x0f00;		// Rd 8-11
		pc_dep = 1;
	} else if (THUMB2_INSN_MATCH (RORW, insn[0]) && (THUMB2_INSN_REG_RN(insn[0]) == 15 || THUMB2_INSN_REG_RM(insn[0]) == 15)) {
		uregs = 0x0f00;
		pc_dep = 1;
	} else if ((THUMB2_INSN_MATCH(ROR, insn[0]) || THUMB2_INSN_MATCH(LSLW2, insn[0]) || THUMB2_INSN_MATCH(LSRW2, insn[0])) && THUMB2_INSN_REG_RM(insn[0]) == 15) {
		uregs = 0x0f00;		// Rd 8-11
		pc_dep = 1;
	} else if ((THUMB2_INSN_MATCH(LSLW1, insn[0]) || THUMB2_INSN_MATCH(LSRW1, insn[0])) && (THUMB2_INSN_REG_RN(insn[0]) == 15 || THUMB2_INSN_REG_RM(insn[0]) == 15)) {
		uregs = 0x0f00;		// Rd 8-11
		pc_dep = 1;
	} else if ((THUMB2_INSN_MATCH(TEQ1, insn[0]) || THUMB2_INSN_MATCH(TST1, insn[0])) && THUMB2_INSN_REG_RN(insn[0]) == 15) {
		uregs = 0xf0000;	//Rn 0-3 (16-19)
		pc_dep = 1;
	} else if ((THUMB2_INSN_MATCH(TEQ2, insn[0]) || THUMB2_INSN_MATCH(TST2, insn[0])) &&
		   (THUMB2_INSN_REG_RN(insn[0]) == 15 || THUMB2_INSN_REG_RM(insn[0]) == 15)) {
		uregs = 0xf0000;	//Rn 0-3 (16-19)
		pc_dep = 1;
	}

	if (unlikely(uregs && pc_dep)) {
		memcpy(insns, pc_dep_insn_execbuf_thumb, 18 * 2);
		if (prep_pc_dep_insn_execbuf_thumb(insns, insn[0], uregs) != 0) {
			printk("Error in %s at %d: failed to prepare exec buffer for insn %lx!",
			       __FILE__, __LINE__, insn[0]);
			p->safe_thumb = -1;
			//free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn_thumb, 0);
			//return -EINVAL;
		}

		addr = ((unsigned int)p->addr) + 4;
		*((unsigned short*)insns + 13) = 0xdeff;
		*((unsigned short*)insns + 14) = addr & 0x0000ffff;
		*((unsigned short*)insns + 15) = addr >> 16;
		if (!is_thumb2(insn[0])) {
			addr = ((unsigned int)p->addr) + 2;
			*((unsigned short*)insns + 16) = (addr & 0x0000ffff) | 0x1;
			*((unsigned short*)insns + 17) = addr >> 16;
		} else {
			addr = ((unsigned int)p->addr) + 4;
			*((unsigned short*)insns + 16) = (addr & 0x0000ffff) | 0x1;
			*((unsigned short*)insns + 17) = addr >> 16;
		}
	} else {
		memcpy(insns, gen_insn_execbuf_thumb, 18 * 2);
		*((unsigned short*)insns + 13) = 0xdeff;
		if (!is_thumb2(insn[0])) {
			addr = ((unsigned int)p->addr) + 2;
			*((unsigned short*)insns + 2) = insn[0];
			*((unsigned short*)insns + 16) = (addr & 0x0000ffff) | 0x1;
			*((unsigned short*)insns + 17) = addr >> 16;
		} else {
			addr = ((unsigned int)p->addr) + 4;
			insns[1] = insn[0];
			*((unsigned short*)insns + 16) = (addr & 0x0000ffff) | 0x1;
			*((unsigned short*)insns + 17) = addr >> 16;
		}
	}

	if (!write_proc_vm_atomic (task, (unsigned long)p->ainsn.insn_thumb, insns, 18 * 2)) {
		panic("failed to write memory %p!\n", p->ainsn.insn_thumb);
		// Mr_Nobody: we have to panic, really??...
		//free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn_thumb, 0);
		//return -EINVAL;
	}

	return 0;
}

int arch_prepare_uprobe(struct kprobe *p, struct task_struct *task, int atomic)
{
	int ret = 0;
	kprobe_opcode_t insn[MAX_INSN_SIZE];

	if ((unsigned long)p->addr & 0x01) {
		printk("Error in %s at %d: attempt to register kprobe at an unaligned address\n", __FILE__, __LINE__);
		return -EINVAL;
	}

	if (!read_proc_vm_atomic(task, (unsigned long)p->addr, &insn, MAX_INSN_SIZE * sizeof(kprobe_opcode_t))) {
		panic("Failed to read memory task[tgid=%u, comm=%s] %p!\n", task->tgid, task->comm, p->addr);
	}

	p->opcode = insn[0];
	p->ainsn.insn_arm = get_insn_slot(task, &uprobe_insn_pages, atomic);
	if (!p->ainsn.insn_arm) {
		printk("Error in %s at %d: kprobe slot allocation error (arm)\n", __FILE__, __LINE__);
		return -ENOMEM;
	}

	ret = arch_copy_trampoline_arm_uprobe(p, task, 1);
	if (ret) {
		free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_arm);
		return -EFAULT;
	}

	p->ainsn.insn_thumb = get_insn_slot(task, &uprobe_insn_pages, atomic);
	if (!p->ainsn.insn_thumb) {
		printk("Error in %s at %d: kprobe slot allocation error (thumb)\n", __FILE__, __LINE__);
		return -ENOMEM;
	}

	ret = arch_copy_trampoline_thumb_uprobe(p, task, 1);
	if (ret) {
		free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_arm);
		free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_thumb);
		return -EFAULT;
	}

	if ((p->safe_arm == -1) && (p->safe_thumb == -1)) {
		printk("Error in %s at %d: failed arch_copy_trampoline_*_uprobe() (both) [tgid=%u, addr=%lx, data=%lx]\n",
		       __FILE__, __LINE__, task->tgid, (unsigned long)p->addr, (unsigned long)p->opcode);
		if (!write_proc_vm_atomic(task, (unsigned long)p->addr, &p->opcode, sizeof(p->opcode))) {
			panic("Failed to write memory %p!\n", p->addr);
		}

		free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_arm);
		free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_thumb);

		return -EFAULT;
	}

	return ret;
}

int setjmp_upre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct jprobe *jp = container_of(p, struct jprobe, kp);
	kprobe_pre_entry_handler_t pre_entry = (kprobe_pre_entry_handler_t)jp->pre_entry;
	entry_point_t entry = (entry_point_t)jp->entry;

	if (pre_entry) {
		p->ss_addr = (kprobe_opcode_t *)pre_entry(jp->priv_arg, regs);
	}

	if (entry) {
		entry(regs->ARM_r0, regs->ARM_r1, regs->ARM_r2,
		      regs->ARM_r3, regs->ARM_r4, regs->ARM_r5);
	} else {
		dbi_arch_uprobe_return();
	}

	prepare_singlestep(p, regs);

	return 1;
}

static int check_validity_insn(struct kprobe *p, struct pt_regs *regs, struct task_struct *task)
{
	struct kprobe *kp;

	if (unlikely(thumb_mode(regs))) {
		if (p->safe_thumb != -1) {
			p->ainsn.insn = p->ainsn.insn_thumb;
			list_for_each_entry_rcu(kp, &p->list, list) {
				kp->ainsn.insn = p->ainsn.insn_thumb;
			}
		} else {
			printk("Error in %s at %d: we are in thumb mode (!) and check instruction was fail \
				(%0lX instruction at %p address)!\n", __FILE__, __LINE__, p->opcode, p->addr);
			// Test case when we do our actions on already running application
			arch_disarm_uprobe(p, task);
			return -1;
		}
	} else {
		if (p->safe_arm != -1) {
			p->ainsn.insn = p->ainsn.insn_arm;
			list_for_each_entry_rcu(kp, &p->list, list) {
				kp->ainsn.insn = p->ainsn.insn_arm;
			}
		} else {
			printk("Error in %s at %d: we are in arm mode (!) and check instruction was fail \
				(%0lX instruction at %p address)!\n", __FILE__, __LINE__, p->opcode, p->addr);
			// Test case when we do our actions on already running application
			arch_disarm_uprobe(p, task);
			return -1;
		}
	}

	return 0;
}

static int uprobe_handler(struct pt_regs *regs)
{
	int err_out = 0;
	char *msg_out = NULL;
	struct task_struct *task = current;
	pid_t tgid = task->tgid;
	kprobe_opcode_t *addr = (kprobe_opcode_t *)(regs->ARM_pc);
	struct kprobe *p = NULL;
	int ret = 0, retprobe = 0;
	struct kprobe_ctlblk *kcb;

#ifdef SUPRESS_BUG_MESSAGES
	int swap_oops_in_progress;
	// oops_in_progress used to avoid BUG() messages that slow down kprobe_handler() execution
	swap_oops_in_progress = oops_in_progress;
	oops_in_progress = 1;
#endif

	p = get_uprobe(addr, tgid);

	if (p && (check_validity_insn(p, regs, task) != 0)) {
		goto no_uprobe_live;
	}

	/* We're in an interrupt, but this is clear and BUG()-safe. */
	kcb = get_kprobe_ctlblk();

	if (p == NULL) {
		p = get_kprobe_by_insn_slot(addr, tgid, regs);
		if (p == NULL) {
			/* Not one of ours: let kernel handle it */
			goto no_uprobe;
		}

		retprobe = 1;
	}

	/* restore opcode for thumb app */
	if (thumb_mode(regs)) {
		if (!is_thumb2(p->opcode)) {
			unsigned long tmp = p->opcode >> 16;
			write_proc_vm_atomic(task, (unsigned long)((unsigned short*)p->addr + 1), &tmp, 2);

			// "2*sizeof(kprobe_opcode_t)" - strange. Should be "sizeof(kprobe_opcode_t)", need to test
			flush_icache_range((unsigned int)p->addr, ((unsigned int)p->addr) + (2 * sizeof(kprobe_opcode_t)));
		}
	}

	set_current_kprobe(p, NULL, NULL);
	kcb->kprobe_status = KPROBE_HIT_ACTIVE;

	if (retprobe) {
		ret = trampoline_probe_handler(p, regs);
	} else if (p->pre_handler) {
		ret = p->pre_handler(p, regs);
		if(p->pre_handler != trampoline_probe_handler) {
			reset_current_kprobe();
		}
	}

	if (ret) {
		/* handler has already set things up, so skip ss setup */
		err_out = 0;
		goto out;
	}

no_uprobe:
	msg_out = "no_uprobe\n";
	err_out = 1; 		// return with death
	goto out;

no_uprobe_live:
	msg_out = "no_uprobe live\n";
	err_out = 0; 		// ok - life is life
	goto out;

out:
#ifdef SUPRESS_BUG_MESSAGES
	oops_in_progress = swap_oops_in_progress;
#endif

	if(msg_out) {
		printk(msg_out);
	}

	return err_out;
}

int uprobe_trap_handler(struct pt_regs *regs, unsigned int instr)
{
	int ret;
	unsigned long flags;
	local_irq_save(flags);

	preempt_disable();
	ret = uprobe_handler(regs);
	preempt_enable_no_resched();

	local_irq_restore(flags);
	return ret;
}

/* userspace probes hook (arm) */
static struct undef_hook undef_hook_for_us_arm = {
	.instr_mask	= 0xffffffff,
	.instr_val	= BREAKPOINT_INSTRUCTION,
	.cpsr_mask	= MODE_MASK,
	.cpsr_val	= USR_MODE,
	.fn		= uprobe_trap_handler
};

/* userspace probes hook (thumb) */
static struct undef_hook undef_hook_for_us_thumb = {
	.instr_mask	= 0xffffffff,
	.instr_val	= BREAKPOINT_INSTRUCTION & 0x0000ffff,
	.cpsr_mask	= MODE_MASK,
	.cpsr_val	= USR_MODE,
	.fn		= uprobe_trap_handler
};

int swap_arch_init_uprobes(void)
{
	swap_register_undef_hook(&undef_hook_for_us_arm);
	swap_register_undef_hook(&undef_hook_for_us_thumb);

	return 0;
}

void swap_arch_exit_uprobes(void)
{
	swap_unregister_undef_hook(&undef_hook_for_us_thumb);
	swap_unregister_undef_hook(&undef_hook_for_us_arm);
}
