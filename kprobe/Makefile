target_kernel_src="/home/kain/dev/inperfa/kernel/tegra/linux-2.6.29-tegra250-9.12.8"
kprobes_module_dir=$(realpath $(top_srcdir)/src/modules/kprobe)

all-local:
	echo "kprobes_module_dir = $(kprobes_module_dir)"
	$(MAKE) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) modules

clean-local:
	$(MAKE) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) clean
