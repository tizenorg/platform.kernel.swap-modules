KERNEL_OBJECTS := ksyms.o swap_ksyms.o
MODULE_NAME=ksyms

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL) SUBDIRS=$(TOP)/$(MODULE_NAME) extra_cflags=-I$(TOP) modules

clean:
	@for f in $(KERNEL_OBJECTS) ; do rm $(TOP)/$(MODULE_NAME)/$$f ; done
