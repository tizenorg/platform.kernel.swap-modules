target_kernel_src=@KERNEL@
target_arch = @ARCH@
handlers_module_dir = $(realpath $(srcdir))
module_name=dalvik_handlers
cross_compiler = $(subst gcc,,$(CC))

all-local:
	cp $(top_srcdir)/src/modules/driver/Module.symvers $(handlers_module_dir)
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) android_opt=$(android_opt) debug_opt=$(debug_opt) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(handlers_module_dir) modules

	echo "generate data for version patching <$(OBJDUMP)><$(READELF)>"
	$(top_srcdir)/src/modules/driver/patchko.sh -g $(handlers_module_dir)/$(module_name).ko $(OBJDUMP) $(READELF)

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(handlers_module_dir) clean

install-exec-local:
	install -m 644 $(handlers_module_dir)/$(module_name).ko $(prefix)
