KERNEL_OBJECTS := swap_us_manager.o us_manager.o us_slot_manager.o helper.o \
                  sspt/ip.o sspt/sspt_page.o sspt/sspt_file.o sspt/sspt_proc.o \
                  pf/proc_filters.o pf/pf_group.o \
                  img/img_proc.o img/img_file.o img/img_ip.o
MODULE_NAME=us_manager

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL) SUBDIRS=$(TOP)/$(MODULE_NAME) extra_cflags=-I$(TOP) modules

clean:
	@for f in $(KERNEL_OBJECTS) ; do rm $(TOP)/$(MODULE_NAME)/$$f ; done
