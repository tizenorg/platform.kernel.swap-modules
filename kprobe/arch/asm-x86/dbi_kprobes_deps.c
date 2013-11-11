/*
 *  Kernel Probes (KProbes)
 *  arch/x86/kernel/kprobes.c
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
 *  modules/kprobe/arch/asm-x86/dbi_kprobes.c
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
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts
 * 2012         Stanislav Andreev <s.andreev@samsung.com>: added time debug profiling support; BUG() message fix
 */

#include <kprobe/dbi_kprobes_deps.h>

DECLARE_MOD_DEP_WRAPPER (module_alloc, void *, unsigned long size)
IMP_MOD_DEP_WRAPPER (module_alloc, size)

DECLARE_MOD_DEP_WRAPPER (module_free, void, struct module *mod, void *module_region)
IMP_MOD_DEP_WRAPPER (module_free, mod, module_region)

DECLARE_MOD_DEP_WRAPPER (fixup_exception, int, struct pt_regs * regs)
IMP_MOD_DEP_WRAPPER (fixup_exception, regs)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26))
DECLARE_MOD_DEP_WRAPPER(text_poke, \
			void, void *addr, unsigned char *opcode, int len)
#else
DECLARE_MOD_DEP_WRAPPER(text_poke, \
			void *, void *addr, const void *opcode, size_t len)
#endif
IMP_MOD_DEP_WRAPPER(text_poke, addr, opcode, len)

DECLARE_MOD_DEP_WRAPPER(show_registers, void, struct pt_regs * regs)
IMP_MOD_DEP_WRAPPER(show_registers, regs)
