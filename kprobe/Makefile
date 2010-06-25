include $(project_pwd)/common.mk

help:
	@$(MAKE) ARCH=$(target_cpu) CROSS_COMPILE=$(target_compiler_prefix) -C $(target_kernel_src) \
		M=$(project_pwd)/$(src_path)/$(kprobe_path) \
		project_pwd=$(project_pwd) help

build:
	@$(MAKE) ARCH=$(target_cpu) CROSS_COMPILE=$(target_compiler_prefix) -C $(target_kernel_src) \
		M=$(project_pwd)/$(src_path)/$(kprobe_path) \
		project_pwd=$(project_pwd) modules

clean:
	@$(MAKE) ARCH=$(target_cpu) CROSS_COMPILE=$(target_compiler_prefix) -C $(target_kernel_src) \
		M=$(project_pwd)/$(src_path)/$(kprobe_path) \
		project_pwd=$(project_pwd) clean
