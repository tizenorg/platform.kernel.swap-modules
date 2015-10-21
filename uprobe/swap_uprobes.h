/**
 * @file uprobe/swap_uprobes.h
 * @author Alexey Gerenkov <a.gerenkov@samsung.com> User-Space Probes initial
 * implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * @author Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for
 * separating core and arch parts
 *
 * @section LICENSE
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
 * @section COPYRIGHT
 *
 * Copyright (C) Samsung Electronics, 2006-2010
 *
 * @section DESCRIPTION
 *
 * Uprobes interface declaration.
 */

#ifndef _SWAP_UPROBES_H
#define _SWAP_UPROBES_H


#include <kprobe/swap_kprobes.h>

#include <swap-asm/swap_uprobes.h>

/**
 * @brief Uprobe pre-handler pointer.
 */
typedef int (*uprobe_pre_handler_t) (struct uprobe *, struct pt_regs *);

/**
 * @brief Uprobe break handler pointer.
 */
typedef int (*uprobe_break_handler_t) (struct uprobe *, struct pt_regs *);

/**
 * @brief Uprobe post handler pointer.
 */
typedef void (*uprobe_post_handler_t) (struct uprobe *,
				       struct pt_regs *,
				       unsigned long flags);

/**
 * @brief Uprobe fault handler pointer.
 */
typedef int (*uprobe_fault_handler_t) (struct uprobe *,
				       struct pt_regs *,
				       int trapnr);

/**
 * @struct uprobe
 * @brief Stores uprobe data.
 */
struct uprobe {
	struct hlist_node hlist; /**< Hash list.*/
	/** List of probes to search by instruction slot.*/
	struct hlist_node is_hlist;
	/** List of uprobes for multi-handler support.*/
	struct list_head list;
	/** Location of the probe point. */
	uprobe_opcode_t *addr;
	/** Called before addr is executed.*/
	uprobe_pre_handler_t pre_handler;
	/** Called after addr is executed, unless...*/
	uprobe_post_handler_t post_handler;
	/** ... called if executing addr causes a fault (eg. page fault).*/
	uprobe_fault_handler_t fault_handler;
	/** Return 1 if it handled fault, otherwise kernel will see it.*/
	uprobe_break_handler_t break_handler;
	/** Saved opcode (which has been replaced with breakpoint).*/
	uprobe_opcode_t opcode;
	/** Override single-step target address, may be used to redirect
	 * control-flow to arbitrary address after probe point without
	 * invocation of original instruction; useful for functions
	 * replacement. If jprobe.entry should return address of function or
	 * NULL if original function should be called.
	 * Not supported for X86, not tested for MIPS. */
	uprobe_opcode_t *ss_addr[NR_CPUS];
#ifdef CONFIG_ARM
	/** Safe/unsafe to use probe on ARM.*/
	unsigned safe_arm:1;
	/** Safe/unsafe to use probe on Thumb.*/
	unsigned safe_thumb:1;
#endif
	struct arch_insn ainsn;              /**< Copy of the original instruction.*/
	struct arch_tramp atramp;            /**< Stores trampoline */
	struct task_struct *task;            /**< Pointer to the task struct */
	struct slot_manager *sm;             /**< Pointer to slot manager */
	bool atomic_ctx;                    /**< Handler context */
};

struct uinst_info {
	struct hlist_node hlist;

	unsigned long vaddr;
	kprobe_opcode_t	opcode;
};

struct urinst_info {
	struct hlist_node hlist;

	struct task_struct *task;
	unsigned long sp;
	unsigned long tramp;
	unsigned long ret_addr;
};

struct uinst_info *uinst_info_create(unsigned long vaddr,
				     kprobe_opcode_t opcode);
void uinst_info_destroy(struct uinst_info *uinst);
void uinst_info_disarm(struct uinst_info *uinst, struct task_struct *task);


void urinst_info_get_current_hlist(struct hlist_head *head, bool recycle);
void urinst_info_put_current_hlist(struct hlist_head *head,
				  struct task_struct *task);


/**
 * @brief Uprobe pre-entry handler.
 */
typedef unsigned long (*uprobe_pre_entry_handler_t)(void *priv_arg,
						    struct pt_regs *regs);

/**
 * @struct ujprobe
 * @brief Stores ujprobe data, based on uprobe.
 */
struct ujprobe {
	struct uprobe up;       /**< Uprobe for this ujprobe */
	void *entry;		/**< Probe handling code to jump to */
	/** Handler which will be called before 'entry' */
	uprobe_pre_entry_handler_t pre_entry;
	void *priv_arg;         /**< Private args for handler */
	char *args;             /**< Function args format string */
};

struct uretprobe_instance;

/**
 * @brief Uretprobe handler.
 */
typedef int (*uretprobe_handler_t)(struct uretprobe_instance *,
				   struct pt_regs *);

/**
 * @strict uretprobe
 * @brief Function-return probe.
 *
 * Note:
 * User needs to provide a handler function, and initialize maxactive.
 */
struct uretprobe {
	struct uprobe up;                   /**< Uprobe for this uretprobe */
	uretprobe_handler_t handler;        /**< Uretprobe handler */
	uretprobe_handler_t entry_handler;  /**< Uretprobe entry handler */
	/** Maximum number of instances of the probed function that can be
	 * active concurrently. */
	int maxactive;
	/** Tracks the number of times the probed function's return was
	 * ignored, due to maxactive being too low. */
	int nmissed;
	size_t data_size;                   /**< Instance data size */
	struct hlist_head free_instances;   /**< Free instances list */
	struct hlist_head used_instances;   /**< Used instances list */

#ifdef CONFIG_ARM
	unsigned arm_noret:1;               /**< No-return flag for ARM */
	unsigned thumb_noret:1;             /**< No-return flag for Thumb */
#endif
};

/**
 * @struct uretprobe_instance
 * @brief Structure for each uretprobe instance.
 */
struct uretprobe_instance {
	/* either on free list or used list */
	struct hlist_node uflist;           /**< Free list */
	struct hlist_node hlist;            /**< Used list */
	struct uretprobe *rp;               /**< Pointer to the parent uretprobe */
	uprobe_opcode_t *ret_addr;          /**< Return address */
	uprobe_opcode_t *sp;                /**< Pointer to stack */
	struct task_struct *task;           /**< Pointer to the task struct */
#ifdef CONFIG_ARM
	/* FIXME Preload: if this flag is set then ignore the thumb_mode(regs)
	 * check in arch_prepare_uretprobe and use thumb trampoline. For the
	 * moment we have to explicitly force arm mode when jumping to preload
	 * handlers but we need the correct (i.e. original) retprobe tramp set
	 * anyway. */
	int preload_thumb;
#endif
	char data[0];                       /**< Custom data */
};

int swap_register_uprobe(struct uprobe *p);
void swap_unregister_uprobe(struct uprobe *p);
void __swap_unregister_uprobe(struct uprobe *up, int disarm);

int swap_register_ujprobe(struct ujprobe *jp);
void swap_unregister_ujprobe(struct ujprobe *jp);
void __swap_unregister_ujprobe(struct ujprobe *jp, int disarm);

int swap_register_uretprobe(struct uretprobe *rp);
void swap_unregister_uretprobe(struct uretprobe *rp);
void __swap_unregister_uretprobe(struct uretprobe *rp, int disarm);

void swap_unregister_all_uprobes(struct task_struct *task);

void swap_ujprobe_return(void);
struct uprobe *get_uprobe(void *addr, pid_t tgid);
struct uprobe *get_uprobe_by_insn_slot(void *addr,
					pid_t tgid,
					struct pt_regs *regs);

void disarm_uprobe(struct uprobe *p, struct task_struct *task);

int trampoline_uprobe_handler(struct uprobe *p, struct pt_regs *regs);

void add_uprobe_table(struct uprobe *p);

#endif /*  _SWAP_UPROBES_H */
