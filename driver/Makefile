target_kernel_src=@KERNEL@
driver_module_dir=$(realpath $(top_srcdir)/src/modules/driver)
module_name=inperfa_driver

all-local:
	$(MAKE) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) modules

clean-local:
	$(MAKE) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) clean

install-exec-local:
	install -m 644 $(driver_module_dir)/$(module_name).ko $(prefix)
