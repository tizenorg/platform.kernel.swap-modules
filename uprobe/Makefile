KERNEL_OBJECTS := swap_uprobe.o swap_uprobes.o arch/asm/swap_uprobes.o arch/asm/trampoline_thumb.o
MODULE_NAME=uprobe

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL) SUBDIRS=$(TOP)/$(MODULE_NAME) extra_cflags=-I$(TOP) modules

clean:
	@for f in $(KERNEL_OBJECTS) ; do rm $(TOP)/$(MODULE_NAME)/$$f ; done
