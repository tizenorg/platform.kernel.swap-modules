KERNEL_OBJECTS := swap_driver.o swap_driver.mod.c swap_driver.mod.o swap_driver_module.o device_driver.o driver_to_buffer.o
MODULE_NAME=driver_new

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL) SUBDIRS=$(TOP)/$(MODULE_NAME) extra_cflags=-I$(TOP) modules

clean:
	@for f in $(KERNEL_OBJECTS) ; do rm $(TOP)/$(MODULE_NAME)/$$f ; done
