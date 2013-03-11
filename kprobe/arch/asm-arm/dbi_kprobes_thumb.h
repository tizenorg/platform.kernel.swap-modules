#ifndef _DBI_KPROBES_THUMB_H
#define _DBI_KPROBES_THUMB_H

void gen_insn_execbuf_thumb(void);
EXPORT_SYMBOL_GPL(gen_insn_execbuf_thumb);

void pc_dep_insn_execbuf_thumb(void);
EXPORT_SYMBOL_GPL(pc_dep_insn_execbuf_thumb);

#endif /* _DBI_KPROBES_THUMB_H */
