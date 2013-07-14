KERNEL_OBJECTS := dbi_kprobes_deps.o dbi_insn_slots.o arch/asm/dbi_kprobes.o dbi_kprobes.o arch/asm/trampoline_arm.o
MODULE_NAME=kprobe

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL) SUBDIRS=$(TOP)/$(MODULE_NAME) extra_cflags=-I$(TOP) modules

clean:
	@for f in $(KERNEL_OBJECTS) ; do rm $(TOP)/$(MODULE_NAME)/$$f ; done
