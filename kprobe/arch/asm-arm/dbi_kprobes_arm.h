#ifndef _DBI_KPROBES_ARM_H
#define _DBI_KPROBES_ARM_H

void kretprobe_trampoline(void);

void gen_insn_execbuf(void);
EXPORT_SYMBOL_GPL(gen_insn_execbuf);

void pc_dep_insn_execbuf(void);
EXPORT_SYMBOL_GPL(pc_dep_insn_execbuf);

#endif /* _DBI_KPROBES_ARM_H */
