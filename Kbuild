extra_cflags := -I$(M) -I$(M)/kprobe/arch/$(LINKNAME)/ -I$(M)/uprobe/arch/$(LINKNAME)/
extra_cflags += $(MCFLAGS)
EXTRA_CFLAGS := $(extra_cflags)
export extra_cflags

obj-m := master/ \
         buffer/ \
         ksyms/ \
         driver/ \
         writer/ \
         kprobe/ \
         ks_manager/ \
         uprobe/ \
         us_manager/ \
         ks_features/ \
         sampler/ \
         energy/ \
         parser/ \
         retprobe/ \
         webprobe/ \
         preload/ \
         fbiprobe/ \
         wsp/ \
         nsp/ \
         task_ctx/
