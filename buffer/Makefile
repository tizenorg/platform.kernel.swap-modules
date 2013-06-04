USER_OBJECTS := buffer_queue_user.o swap_buffer_user.o
USER_FLAG := BUFFER_FOR_USER
KERNEL_OBJECTS := buffer_queue.o swap_buffer_module.o
KERNEL_FILES := swap_buffer.o swap_buffer.mod.c swap_buffer.mod.o
obj-m = $(KERNEL_OBJECTS)
#CC=gcc
CC=/home/alexander/dev/u1_slp/arm-linux-gnueabi-gcc4.4.1-glibc2.11.1/bin/arm-none-linux-gnueabi-gcc
#KERNEL_PATH=/home/alexander/dev/u1_slp/kernel_20121005
KERNEL_PATH=/home/alexander/vanilla_kernels/linux-3.8.6

kernel:
	make ARCH=arm CROSS_COMPILE=/home/alexander/dev/u1_slp/arm-linux-gnueabi-gcc4.4.1-glibc2.11.1/bin/arm-none-linux-gnueabi- -C $(KERNEL_PATH) SUBDIRS=$(PWD) modules

clean:
	rm $(KERNEL_OBJECTS) $(KERNEL_FILES)
