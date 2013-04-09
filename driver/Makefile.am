if MEMCHECKER
memchecker = -DMEMORY_CHECKER
endif

if DEBUG
debug_opt = -D__DEBUG
endif

if SPARSE
sparse_output = C=2
endif

if ANDROID
android_opt = -D__ANDROID
android = yes
else
dev_path = @TARGET_DEVICE_PATH@
endif

if ANDROID_APP
android_app_opt = -DANDROID_APP
endif

board_opt = -DBOARD_@BOARD@

target_kernel_src = @KERNEL@
target_arch = @ARCH@
driver_module_dir = $(realpath $(srcdir))
module_name = swap_driver
cross_compiler = $(subst gcc,,$(CC))

inlude_opt = -I$(realpath $(top_srcdir)/src/modules/ksyms) \
             -I$(realpath $(top_srcdir)/src/common) \
             -I$(realpath $(top_srcdir)/src/profile) \
             -I$(realpath $(top_srcdir)/src/modules/kprobe) \
             -I$(realpath $(top_srcdir)/src/modules/kprobe/arch) \
             -I$(realpath $(top_srcdir)/src/modules/uprobe)
extra_cflags = "$(inlude_opt) -DEC_ARCH_$(ARCH) -D__DEBUG $(memchecker) $(debug_opt) $(android_opt) $(slp_opt) $(android_app_opt) $(board_opt)"

#bin_SCRIPTS = patchko.sh insmod.sh

all-local:
	cp $(top_srcdir)/src/modules/kprobe/Module.symvers $(driver_module_dir)
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) extra_cflags=$(extra_cflags) $(AM_MAKEFLAGS) -C $(target_kernel_src) $(sparse_output) M=$(driver_module_dir) modules

	echo "generate data for version patching <$(OBJDUMP)><$(READELF)>"
	$(top_srcdir)/src/modules/driver/patchko.sh -g $(driver_module_dir)/$(module_name).ko $(OBJDUMP) $(READELF)

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) clean

install-exec-local:

	install -m 644 $(driver_module_dir)/$(module_name).ko $(prefix)
	install -m 644 $(driver_module_dir)/$(module_name).ko.addr $(prefix)
	install -m 755 $(driver_module_dir)/patchko.sh $(prefix)/bin
	install -m 755 $(driver_module_dir)/insmod.sh $(prefix)/bin

	if [ "$(android)" != "yes" ] ; then \
	sed "s|__DEV_NAME__|`basename $(dev_path)`|" $(driver_module_dir)/$(module_name).sh | \
	sed "s|__DEV_DIR__|`dirname $(dev_path)`|" > \
	$(prefix)/$(module_name).sh ; chmod +x $(prefix)/$(module_name).sh ; \
	chmod +x $(driver_module_dir)/patchko.sh ; \
	chmod +x $(driver_module_dir)/insmod.sh ; \
	fi
