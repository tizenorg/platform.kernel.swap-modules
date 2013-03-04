if DEBUG
debug_opt = -D__DEBUG
endif

if SPARSE
sparse_output = C=2
endif

board_opt = -DBOARD_@BOARD@

target_kernel_src = @KERNEL@
target_arch = @ARCH@
module_dir = $(realpath $(srcdir))
module_name = swap_buffer
cross_compiler = $(subst gcc,,$(CC))

inlude_opt = -I$(top_srcdir)/src/modules/ksyms -I$(top_srcdir)/src/common -I$(top_srcdir)/src/profile
extra_cflags = "$(inlude_opt) -DEC_ARCH_$(ARCH) $(debug_opt) $(board_opt)"

#bin_SCRIPTS = patchko.sh insmod.sh

all-local:
	cp $(top_srcdir)/src/modules/kprobe/Module.symvers $(module_dir)
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) extra_cflags=$(extra_cflags) $(AM_MAKEFLAGS) -C $(target_kernel_src) $(sparse_output) M=$(module_dir) modules

	echo "generate data for version patching <$(OBJDUMP)><$(READELF)>"
	$(top_srcdir)/src/modules/driver/patchko.sh -g $(module_dir)/$(module_name).ko $(OBJDUMP) $(READELF)

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(module_dir) clean

install-exec-local:
	install -m 644 $(module_dir)/$(module_name).ko $(prefix)
	install -m 644 $(module_dir)/$(module_name).ko.addr $(prefix)
