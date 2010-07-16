target_kernel_src = @KERNEL@
driver_module_dir = $(realpath $(top_srcdir)/src/modules/driver)
module_name = inperfa_driver
cross_compiler = $(subst gcc,,$(CC))

all-local:
	cp $(top_srcdir)/src/modules/kprobe/Module.symvers $(driver_module_dir)
	CROSS_COMPILE=$(cross_compiler) $(MAKE) ARCH=arm memchecker=$(memchecker) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) modules

clean-local:
	CROSS_COMPILE=$(cross_compiler) $(MAKE) ARCH=arm $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) clean

install-exec-local:
	install -m 644 $(driver_module_dir)/$(module_name).ko $(prefix)
	install -m 755 $(driver_module_dir)/$(module_name).sh $(prefix)
