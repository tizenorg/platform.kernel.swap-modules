target_kernel_src=@KERNEL@
kprobes_module_dir=$(realpath $(top_srcdir)/src/modules/kprobe)
module_name=inperfa_kprobe

all-local:
	echo "kprobes_module_dir = $(kprobes_module_dir)"
	$(MAKE) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) modules

clean-local:
	$(MAKE) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) clean

install-exec-local:
	install -m 644 $(kprobes_module_dir)/$(module_name).ko $(prefix)
