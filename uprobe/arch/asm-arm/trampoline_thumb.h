/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/uprobe/arch/asm-arm/trampoline_thumb.h
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
 *
 */


#ifndef __ASM_ARM_TRAMPOLINE_THUMB_H
#define __ASM_ARM_TRAMPOLINE_THUMB_H

void gen_insn_execbuf_thumb(void);
void pc_dep_insn_execbuf_thumb(void);
void b_r_insn_execbuf_thumb(void);
void b_off_insn_execbuf_thumb(void);
void blx_off_insn_execbuf_thumb(void);
void b_cond_insn_execbuf_thumb(void);
void cbz_insn_execbuf_thumb(void);

#endif /* __ASM_ARM_TRAMPOLINE_THUMB_H */
