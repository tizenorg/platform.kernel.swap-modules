#ifndef _CPU_CTRL_H_
#define _CPU_CTRL_H_

struct cpumask;

#ifdef CONFIG_SMP
int swap_disable_nonboot_cpus_lock(struct cpumask *mask);
int swap_enable_nonboot_cpus_unlock(struct cpumask *mask);

int init_cpu_deps(void);

#else /* CONFIG_SMP */

static inline int swap_disable_nonboot_cpus_lock(struct cpumask *mask)
{
	return 0;
}

static inline int swap_enable_nonboot_cpus_unlock(struct cpumask *mask)
{
	return 0;
}

static inline int init_cpu_deps(void)
{
	return 0;
}

#endif /* CONFIG_SMP */

#endif /* _CPU_CTRL_H_ */
