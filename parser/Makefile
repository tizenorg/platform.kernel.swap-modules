KERNEL_OBJECTS := swap_msg_parser.o msg_parser.o msg_buf.o msg_cmd.o features.o us_inst.o swap_message_parser.o
MODULE_NAME=parser

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL) SUBDIRS=$(TOP)/$(MODULE_NAME) extra_cflags=-I$(TOP) modules

clean:
	@for f in $(KERNEL_OBJECTS) ; do rm $(TOP)/$(MODULE_NAME)/$$f ; done
