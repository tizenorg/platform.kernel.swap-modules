KERNEL_OBJECTS := swap_buffer.o swap_buffer_module.o buffer_queue.o
MODULE_NAME=buffer

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL) SUBDIRS=$(TOP)/$(MODULE_NAME) extra_cflags=-I$(TOP) modules

clean:
	@for f in $(KERNEL_OBJECTS) ; do rm $(TOP)/$(MODULE_NAME)/$$f ; done
