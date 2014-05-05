#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <ksyms/ksyms.h>

#ifdef CONFIG_SMP
static void (*swap_cpu_maps_update_begin)(void);
static void (*swap_cpu_maps_update_done)(void);
static int (*swap_cpu_down)(unsigned int, int);
static int (*swap_cpu_up)(unsigned int, int);

int swap_disable_nonboot_cpus_lock(struct cpumask *mask)
{
	int boot_cpu, cpu;
	int ret = 0;

	swap_cpu_maps_update_begin();
	cpumask_clear(mask);

	boot_cpu = cpumask_first(cpu_online_mask);

	for_each_online_cpu(cpu) {
		if (cpu == boot_cpu)
			continue;
		ret = swap_cpu_down(cpu, 0);
		if (ret == 0)
			cpumask_set_cpu(cpu, mask);
		printk("===> SWAP CPU[%d] down(%d)\n", cpu, ret);
	}

	WARN_ON(num_online_cpus() > 1);
	return ret;
}

int swap_enable_nonboot_cpus_unlock(struct cpumask *mask)
{
	int cpu, ret = 0;

	if (cpumask_empty(mask))
		goto out;

	for_each_cpu(cpu, mask) {
		ret = swap_cpu_up(cpu, 0);
		printk("===> SWAP CPU[%d] up(%d)\n", cpu, ret);
	}

	swap_cpu_maps_update_done();

out:
	return ret;
}

int init_cpu_deps(void)
{
	const char *sym = "cpu_maps_update_begin";

	swap_cpu_maps_update_begin = (void *)swap_ksyms(sym);
	if (!swap_cpu_maps_update_begin)
		goto not_found;

	sym = "cpu_maps_update_done";
	swap_cpu_maps_update_done = (void *)swap_ksyms(sym);
	if (!swap_cpu_maps_update_done)
		goto not_found;

	sym = "_cpu_up";
	swap_cpu_up = (void *)swap_ksyms(sym);
	if (!swap_cpu_up)
		goto not_found;

	sym = "_cpu_down";
	swap_cpu_down = (void *)swap_ksyms(sym);
	if (!swap_cpu_down)
		goto not_found;

	return 0;

not_found:
	printk("ERROR: symbol %s(...) not found\n", sym);
	return -ESRCH;
}

#endif /* CONFIG_SMP */
