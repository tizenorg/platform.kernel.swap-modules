target_kernel_src = @KERNEL@
kprobes_module_dir = $(realpath $(top_srcdir)/src/modules/kprobe)
module_name = inperfa_kprobe
cross_compiler = $(subst gcc,,$(CC))

all-local:
	CROSS_COMPILE=$(cross_compiler) $(MAKE) ARCH=arm $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) modules

clean-local:
	CROSS_COMPILE=$(cross_compiler) $(MAKE) ARCH=arm $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) clean

install-exec-local:
	install -m 644 $(kprobes_module_dir)/$(module_name).ko $(prefix)
