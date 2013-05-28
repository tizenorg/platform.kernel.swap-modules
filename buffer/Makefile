USER_OBJECTS := buffer_queue_user.o swap_buffer_user.o space_dep_operations_user.o
USER_FLAG := BUFFER_FOR_USER
KERNEL_OBJECTS := buffer_queue.o swap_buffer_module.o space_dep_operations.o
KERNEL_FILES := swap_buffer.o swap_buffer.mod.c swap_buffer.mod.o
obj-m = $(KERNEL_OBJECTS)
#CC=gcc
CC=/home/alexander/dev/u1_slp/arm-linux-gnueabi-gcc4.4.1-glibc2.11.1/bin/arm-none-linux-gnueabi-gcc
KERNEL_PATH=/home/alexander/dev/u1_slp/kernel_20121005
#KERNEL_PATH=/home/alexander/vanilla_kernels/linux-3.8.6

kernel:
	make ARCH=arm CROSS_COMPILE=/home/alexander/dev/u1_slp/arm-linux-gnueabi-gcc4.4.1-glibc2.11.1/bin/arm-none-linux-gnueabi- -C $(KERNEL_PATH) SUBDIRS=$(PWD) modules

libswap_buffer.so: $(USER_OBJECTS)
	$(CC) -shared -lpthread -Wl,-soname,libswap_buffer.so -o libswap_buffer.so $(USER_OBJECTS)

swap_buffer_user.o: swap_buffer_module.c
	$(CC) -c -fPIC swap_buffer_module.c -D$(USER_FLAG) -o swap_buffer_user.o

buffer_queue_user.o: buffer_queue.c
	$(CC) -c -fPIC buffer_queue.c -D$(USER_FLAG) -o buffer_queue_user.o

space_dep_operations_user.o: space_dep_operations.c
	$(CC) -c -fPIC space_dep_operations.c -D$(USER_FLAG) -o space_dep_operations_user.o

clean:
	rm $(USER_OBJECTS) $(KERNEL_OBJECTS) $(KERNEL_FILES)
