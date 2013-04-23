board_opt = -DBOARD_@BOARD@
target_kernel_src = @KERNEL@
target_arch = @ARCH@
module_dir = $(realpath $(top_srcdir)/src/modules/ks_manager)
module_name = swap_ks_manager
cross_compiler = $(subst gcc,,$(CC))

extra_cflags = "$(board_opt)"

all-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) extra_cflags=$(extra_cflags) \
	        $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(module_dir) modules

	echo "generate data for version patching <$(OBJDUMP)><$(READELF)>"
	PATH=$(PATH) $(top_srcdir)/src/modules/driver/patchko.sh -g $(module_dir)/$(module_name).ko $(OBJDUMP) $(READELF)

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(module_dir) clean

install-exec-local:
	install -m 644 $(module_dir)/$(module_name).ko $(prefix)
	install -m 644 $(module_dir)/$(module_name).ko.addr $(prefix)
	install -m 755 $(module_dir)/$(module_name).sh $(prefix)
