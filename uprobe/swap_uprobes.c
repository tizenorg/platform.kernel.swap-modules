#include <linux/module.h>

static int __init init_uprobes(void)
{
	return 0;
}

static void __exit exit_uprobes(void)
{
}

module_init(init_uprobes);
module_exit(exit_uprobes);

MODULE_LICENSE ("GPL");
