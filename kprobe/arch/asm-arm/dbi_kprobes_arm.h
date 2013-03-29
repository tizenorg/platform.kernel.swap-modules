#ifndef _DBI_KPROBES_ARM_H
#define _DBI_KPROBES_ARM_H

void kretprobe_trampoline(void);
void gen_insn_execbuf(void);
void pc_dep_insn_execbuf(void);

#endif /* _DBI_KPROBES_ARM_H */
