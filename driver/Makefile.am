if MEMCHECKER
memchecker = -DMEMORY_CHECKER
endif

if DEBUG
debug_opt = -D__DEBUG
endif

if ANDROID
android_opt = -D__ANDROID
android = yes
else
dev_major = @TARGET_DEVICE_MAJOR@
dev_path = @TARGET_DEVICE_PATH@
endif

if SLP_APP
slp_opt = -DSLP_APP
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

all-local:
	cp $(top_srcdir)/src/modules/kprobe/Module.symvers $(driver_module_dir)
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) memchecker=$(memchecker) android_opt=$(android_opt) slp_opt=$(slp_opt) android_app_opt=$(android_app_opt) board_opt=$(board_opt) debug_opt=$(debug_opt) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) modules

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(driver_module_dir) clean

install-exec-local:
	install -m 644 $(driver_module_dir)/$(module_name).ko $(prefix)
	if [ "$(android)" != "yes" ] ; then \
	sed "s|__DEV_MAJOR__|$(dev_major)|" $(driver_module_dir)/$(module_name).sh | \
	sed "s|__DEV_NAME__|`basename $(dev_path)`|" | \
	sed "s|__DEV_DIR__|`dirname $(dev_path)`|" > \
	$(prefix)/$(module_name).sh ; chmod +x $(prefix)/$(module_name).sh ; fi
