target_kernel_src="/home/kain/dev/inperfa/kernel/tegra/linux-2.6.29-tegra250-9.12.8"
driver_module_dir=$(realpath $(top_srcdir)/src/modules/driver)

all-local:
	$(MAKE) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) modules

clean-local:
	$(MAKE) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) clean
