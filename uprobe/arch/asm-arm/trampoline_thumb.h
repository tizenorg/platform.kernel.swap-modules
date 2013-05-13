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
