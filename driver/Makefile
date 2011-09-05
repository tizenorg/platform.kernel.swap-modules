target_kernel_src = @KERNEL@
target_arch = @ARCH@
#board = @BOARD@
driver_module_dir = $(realpath $(srcdir))
module_name = inperfa_driver
cross_compiler = $(subst gcc,,$(CC))

all-local:
	cp $(top_srcdir)/src/modules/kprobe/Module.symvers $(driver_module_dir)
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) memchecker=$(memchecker) android_opt=$(android_opt) slp_opt=$(slp_opt) android_app_opt=$(android_app_opt) board_opt=$(board_opt) debug_opt=$(debug_opt) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) modules

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) clean

install-exec-local:
	install -m 644 $(driver_module_dir)/$(module_name).ko $(prefix)
	if [ "$(android)" != "yes" ] ; then install -m 755 $(driver_module_dir)/$(module_name).sh $(prefix) ; fi

