if ANDROID
android_opt = -D__ANDROID
android = yes
endif

if SPARSE
sparse_output = C=2
endif

board_opt = -DBOARD_@BOARD@

target_kernel_src = @KERNEL@
#board = @BOARD@
target_arch = @ARCH@
kprobes_module_dir = $(realpath $(top_srcdir)/src/modules/kprobe)
module_name = swap_kprobe
cross_compiler = $(subst gcc,,$(CC))

inlude_opt = -I$(realpath $(top_srcdir)/src/modules/ksyms)
extra_cflags = "$(inlude_opt) $(android_opt) $(board_opt)"

all-local:
	rm -rf $(top_srcdir)/src/modules/kprobe/arch/asm && $(LN_S) asm-${target_arch} $(top_srcdir)/src/modules/kprobe/arch/asm
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) extra_cflags=$(extra_cflags) $(AM_MAKEFLAGS) -C $(target_kernel_src) $(sparse_output) M=$(kprobes_module_dir) modules


	echo "generate data for version patching <$(OBJDUMP)><$(READELF)>"
	PATH=$(PATH) $(top_srcdir)/src/modules/driver/patchko.sh -g $(kprobes_module_dir)/$(module_name).ko $(OBJDUMP) $(READELF)

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(kprobes_module_dir) clean

install-exec-local:

	install -m 644 $(kprobes_module_dir)/$(module_name).ko $(prefix)
	install -m 644 $(kprobes_module_dir)/$(module_name).ko.addr $(prefix)

	if [ "$(android)" != "yes" ] ; then install -m 755 $(kprobes_module_dir)/$(module_name).sh $(prefix) ; fi


