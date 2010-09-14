#include "kprobe_deps.h"

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
