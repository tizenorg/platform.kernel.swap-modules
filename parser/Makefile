KERNEL_OBJECTS := swap_message_parser.o swap_message_parser.mod.c swap_message_parser.mod.o swap_message_parser_module.o message_parser.o message_handler.o
#TOOLCHAIN :=/home/alexander/dev/u1_slp/arm-linux-gnueabi-gcc4.4.1-glibc2.11.1/bin/arm-none-linux-gnueabi-
TOOLCHAIN := /home/alexander/dev/qemu/buildroot-2013.02/output/host/usr/bin/arm-buildroot-linux-uclibcgnueabi-
#KERNEL := /home/alexander/dev/u1_slp/kernel_20121005 
#KERNEL := /home/alexander/vanilla_kernels/linux-3.8.6
KERNEL := /home/alexander/dev/linux-3.4-exynos
CC := /home/alexander/dev/u1_slp/arm-linux-gnueabi-gcc4.4.1-glibc2.11.1/bin/arm-none-linux-gnueabi-gcc
obj-m := swap_parser_module.o

all:
	make ARCH=arm CROSS_COMPILE=$(TOOLCHAIN) -C $(KERNEL) SUBDIRS=$(PWD) modules

clean:
	rm $(KERNEL_OBJECTS)
