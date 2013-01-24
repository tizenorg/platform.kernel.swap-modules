target_kernel_src = @KERNEL@
target_arch = @ARCH@
module_dir = $(realpath $(top_srcdir)/src/modules/ksyms)
module_name = swap_ksyms
cross_compiler = $(subst gcc,,$(CC))
module_path = $(module_dir)/$(module_name).ko


all-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(module_dir) modules

	if [ -e $(module_path) ] ; then \
		echo "generate data for version patching <$(OBJDUMP)><$(READELF)>" ; \
		PATH=$(PATH) $(top_srcdir)/src/modules/driver/patchko.sh -g $(module_dir)/$(module_name).ko $(OBJDUMP) $(READELF) ; \
	fi

clean-local:
	$(MAKE) CROSS_COMPILE=$(cross_compiler) ARCH=$(target_arch) $(AM_MAKEFLAGS) -C $(target_kernel_src) M=$(module_dir) clean

install-exec-local:
	if [ -e $(module_path) ] ; then \
		install -m 644 $(module_path) $(prefix) ; \
		install -m 644 $(module_path).addr $(prefix) ; \
	\
		if [ "$(android)" != "yes" ] ; then install -m 755 $(module_dir)/$(module_name).sh $(prefix) ; fi ; \
	fi
