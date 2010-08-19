target_kernel_src = @KERNEL@
target_arch = @ARCH@
kprobes_module_dir = $(realpath $(srcdir))
module_name = inperfa_kprobe
cross_compiler = $(subst gcc,,$(CC))

all-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) modules

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) clean

install-exec-local:
	install -m 644 $(kprobes_module_dir)/$(module_name).ko $(prefix)
	install -m 755 $(kprobes_module_dir)/$(module_name).sh $(prefix)
