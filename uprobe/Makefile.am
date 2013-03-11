board_opt = -DBOARD_@BOARD@
target_kernel_src = @KERNEL@
target_arch = @ARCH@
uprobes_module_dir = $(realpath $(top_srcdir)/src/modules/uprobe)
module_name = swap_uprobe
cross_compiler = $(subst gcc,,$(CC))

inlude_opt = -I$(realpath $(top_srcdir)/src/modules/ksyms) -I$(realpath $(top_srcdir)/src/modules/kprobe) \
             -I$(realpath $(top_srcdir)/src/modules/kprobe/arch) -I$(realpath $(top_srcdir)/src/modules/uprobe/arch)
extra_cflags = "$(inlude_opt) $(android_opt) $(board_opt)"

all-local:
	rm -rf $(top_srcdir)/src/modules/uprobe/arch/asm && $(LN_S) asm-${target_arch} $(top_srcdir)/src/modules/uprobe/arch/asm
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) extra_cflags=$(extra_cflags) \
	        $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(uprobes_module_dir) modules

	echo "generate data for version patching <$(OBJDUMP)><$(READELF)>"
	PATH=$(PATH) $(top_srcdir)/src/modules/driver/patchko.sh -g $(uprobes_module_dir)/$(module_name).ko $(OBJDUMP) $(READELF)

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(uprobes_module_dir) clean

install-exec-local:
	install -m 644 $(uprobes_module_dir)/$(module_name).ko $(prefix)
	install -m 644 $(uprobes_module_dir)/$(module_name).ko.addr $(prefix)

	if [ "$(android)" != "yes" ] ; then install -m 755 $(uprobes_module_dir)/$(module_name).sh $(prefix) ; fi
