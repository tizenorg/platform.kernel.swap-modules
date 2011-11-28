////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           probes_manager.c
//
//      DESCRIPTION:
//      This file is C source for SWAP driver.
//
//      SEE ALSO:       probes_manager.h
//      AUTHOR:         L.Komkov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#include <linux/percpu.h>
#include "module.h"
#include "probes_manager.h"

#ifdef EC_ARCH_arm
/* ARCH == arm */
#include "../kprobe/dbi_kprobes.h"
#endif /* def EC_ARCH_arm */

#ifdef EC_ARCH_i386
/* ARCH == i386 */
//#include <linux/kprobes.h>
#include "../kprobe/dbi_kprobes.h"
#endif /* def EC_ARCH_i386 */

#ifdef EC_ARCH_mips
/* ARCH == mips */
#include "../kprobe/dbi_kprobes.h"
#endif /* def EC_ARCH_mips */

unsigned long pf_addr;
unsigned long exit_addr;
unsigned long fork_addr;
unsigned long exec_addr;
kernel_probe_t *pf_probe = NULL;
kernel_probe_t *exit_probe = NULL;
kernel_probe_t *fork_probe = NULL;
kernel_probe_t *exec_probe = NULL;
unsigned int probes_flags = 0;

int
probes_manager_init (void)
{
#ifdef CONFIG_X86
	pf_addr = lookup_name("handle_mm_fault");
#else
	pf_addr = lookup_name("do_page_fault");
#endif
	if (pf_addr == 0) {
		EPRINTF("Cannot find address for page fault function!");
		return -EINVAL;
	}

	exit_addr = lookup_name("do_exit");
	if (exit_addr == 0) {
		EPRINTF("Cannot find address for do_exit function!");
		return -EINVAL;
	}

	fork_addr = lookup_name("do_fork");
	if (exit_addr == 0) {
		EPRINTF("Cannot find address for do_fork function!");
		return -EINVAL;
	}

	exec_addr = lookup_name("do_execve");
	if (exec_addr == 0) {
		EPRINTF("Cannot find address for do_execve function!");
		return -EINVAL;
	}

	return storage_init ();
}

void
probes_manager_down (void)
{
	detach_selected_probes ();
	storage_down ();
}

static int
register_kernel_jprobe (kernel_probe_t * probe)
{
	int result;
	if (((probe == pf_probe) && (us_proc_probes & US_PROC_PF_INSTLD)) ||
	    ((probe == fork_probe) && (us_proc_probes & US_PROC_FORK_INSTLD)) ||
	    ((probe == exec_probe) && (us_proc_probes & US_PROC_EXEC_INSTLD)) ||
	    ((probe == exit_probe) && (us_proc_probes & US_PROC_EXIT_INSTLD)))
	{
		return 0;	// probe is already registered
	}
	result = register_jprobe (&probe->jprobe, 0);
	if (result)
	{
		EPRINTF ("register_kernel_jprobe(0x%lx) failure %d", probe->addr, result);
		return result;
	}
	return 0;
}

static int
unregister_kernel_jprobe (kernel_probe_t * probe)
{
	if (((probe == pf_probe) && (us_proc_probes & US_PROC_PF_INSTLD)) ||
		((probe == exit_probe) && (us_proc_probes & US_PROC_EXIT_INSTLD)) ||
		((probe == fork_probe) && (us_proc_probes & US_PROC_FORK_INSTLD)) ||
		((probe == exec_probe) && (us_proc_probes & US_PROC_EXEC_INSTLD))) {
		return 0;	// probe is necessary for user space instrumentation
	}
	unregister_jprobe (&probe->jprobe, 0);
	return 0;
}

static int
register_kernel_retprobe (kernel_probe_t * probe)
{
	int result;
	if (((probe == pf_probe) && (us_proc_probes & US_PROC_PF_INSTLD)) ||
		((probe == exit_probe) && (us_proc_probes & US_PROC_EXIT_INSTLD)) ||
		((probe == fork_probe) && (us_proc_probes & US_PROC_FORK_INSTLD)) ||
		((probe == exec_probe) && (us_proc_probes & US_PROC_EXEC_INSTLD))) {
		return 0;	// probe is already registered
	}

	result = register_kretprobe (&probe->retprobe, 0);
	if (result)
	{
		EPRINTF ("register_kernel_retprobe(0x%lx) failure %d", probe->addr, result);
		return result;
	}
	return 0;
}

static int
unregister_kernel_retprobe (kernel_probe_t * probe)
{
	if (((probe == pf_probe) && (us_proc_probes & US_PROC_PF_INSTLD)) ||
		((probe == exit_probe) && (us_proc_probes & US_PROC_EXIT_INSTLD)) ||
		((probe == fork_probe) && (us_proc_probes & US_PROC_FORK_INSTLD)) ||
		((probe == exec_probe) && (us_proc_probes & US_PROC_EXEC_INSTLD))) {
		return 0;	// probe is necessary for user space instrumentation
	}
	unregister_kretprobe (&probe->retprobe, 0);
	return 0;
}

int
register_kernel_probe (kernel_probe_t * probe)
{
	register_kernel_jprobe (probe);
	register_kernel_retprobe (probe);
	return 0;
}

int
unregister_kernel_probe (kernel_probe_t * probe)
{
	unregister_kernel_jprobe (probe);
	unregister_kernel_retprobe (probe);
	return 0;
}

int
attach_selected_probes (void)
{
	int result = 0;
	int partial_result = 0;
	kernel_probe_t *p;
	struct hlist_node *node;

	hlist_for_each_entry_rcu (p, node, &kernel_probes, hlist)
	{
		partial_result = register_kernel_probe (p);
		if (partial_result)
		{
			result = partial_result;
			detach_selected_probes ();	// return into safe state
			break;
		}
	}

	return result;
}

int
detach_selected_probes (void)
{
	kernel_probe_t *p;
	struct hlist_node *node;

	hlist_for_each_entry_rcu (p, node, &kernel_probes, hlist)
		unregister_kernel_probe (p);

	return 0;
}

int
add_probe (unsigned long addr)
{
	int result = 0;
	kernel_probe_t **pprobe = NULL;

	DPRINTF("add probe at 0x%0x\n", addr);
	if (EC_STATE_IDLE != ec_info.ec_state)
	{
		EPRINTF("Probes addition is allowed in IDLE state only.");
		return -EINVAL;
	}

	if (addr == pf_addr) {
		probes_flags |= PROBE_FLAG_PF_INSTLD;
		if (us_proc_probes & US_PROC_PF_INSTLD)
		{
			return 0;
		}
		pprobe = &pf_probe;
	}
	else if (addr == exit_addr) {
		probes_flags |= PROBE_FLAG_EXIT_INSTLD;
		if (us_proc_probes & US_PROC_EXIT_INSTLD)
		{
			return 0;
		}
		pprobe = &exit_probe;
	}
	else if (addr == fork_addr) {
		probes_flags |= PROBE_FLAG_FORK_INSTLD;
		if (us_proc_probes & US_PROC_FORK_INSTLD)
		{
			return 0;
		}
		pprobe = &fork_probe;
	}
	else if (addr == exec_addr) {
		probes_flags |= PROBE_FLAG_EXEC_INSTLD;
		if (us_proc_probes & US_PROC_EXEC_INSTLD) {
			return 0;
		}
		pprobe = &exit_probe;
	}

	result = add_probe_to_list (addr, pprobe);
	if (result) {
		if (addr == pf_addr)
			probes_flags &= ~PROBE_FLAG_PF_INSTLD;
		else if (addr == exit_addr)
			probes_flags &= ~PROBE_FLAG_EXIT_INSTLD;
		else if (addr == fork_addr)
			probes_flags &= ~PROBE_FLAG_FORK_INSTLD;
		else if (addr == exec_addr)
			probes_flags &= ~PROBE_FLAG_EXEC_INSTLD;
	}
	return result;
}

int reset_probes()
{
	struct hlist_node *node, *tnode;
	kernel_probe_t *p;

	hlist_for_each_entry_safe (p, node, tnode, &kernel_probes, hlist) {
		if (p->addr == pf_addr) {
			probes_flags &= ~PROBE_FLAG_PF_INSTLD;
			pf_probe = NULL;
		} else if (p->addr == exit_addr) {
			probes_flags &= ~PROBE_FLAG_EXIT_INSTLD;
			exit_probe = NULL;
		} else if (p->addr == fork_addr) {
			probes_flags &= ~PROBE_FLAG_FORK_INSTLD;
			fork_probe = NULL;
		} else if (p->addr == exec_addr) {
			probes_flags &= ~PROBE_FLAG_EXEC_INSTLD;
			exec_probe = NULL;
		}
		hlist_del(node);
		kfree(p);
	}

	return 0;
}

int
remove_probe (unsigned long addr)
{
	int result = 0;

	if (EC_STATE_IDLE != ec_info.ec_state)
	{
		EPRINTF("Probes addition is allowed in IDLE state only.");
		return -EINVAL;
	}

	if (addr == pf_addr) {
		probes_flags &= ~PROBE_FLAG_PF_INSTLD;
		if (us_proc_probes & US_PROC_PF_INSTLD)
		{
			return 0;
		}
		pf_probe = NULL;
	}
	else if (addr == exit_addr) {
		probes_flags &= ~PROBE_FLAG_EXIT_INSTLD;
		if (us_proc_probes & US_PROC_EXIT_INSTLD)
		{
			return 0;
		}
		exit_probe = NULL;
	}
	else if (addr == fork_addr) {
		probes_flags &= ~PROBE_FLAG_FORK_INSTLD;
		if (us_proc_probes & US_PROC_FORK_INSTLD)
		{
			return 0;
		}
		fork_probe = NULL;
	}
	else if (addr == exec_addr) {
		probes_flags &= ~PROBE_FLAG_EXEC_INSTLD;
		if (us_proc_probes & US_PROC_EXEC_INSTLD) {
			return 0;
		}
		exec_probe = NULL;
	}

	result = remove_probe_from_list (addr);

	return result;
}

DEFINE_PER_CPU (kernel_probe_t *, gpKernProbe) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpKernProbe);
DEFINE_PER_CPU(struct pt_regs *, gpKernRegs) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpKernRegs);

unsigned long
def_jprobe_event_pre_handler (kernel_probe_t * probe, struct pt_regs *regs)
{
	__get_cpu_var (gpKernProbe) = probe;
	__get_cpu_var (gpKernRegs) = regs;

	return 0;
}

void
def_jprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	//static int nCount;
	kernel_probe_t *probe = __get_cpu_var(gpKernProbe);
	int skip = 0;

	if (pf_probe == probe)
	{
		if (!(probes_flags & PROBE_FLAG_PF_INSTLD))
			skip = 1;
	}
	else if (exit_probe == probe)
	{
		if (us_proc_probes & US_PROC_EXIT_INSTLD)
			do_exit_probe_pre_code ();
		if (!(probes_flags & PROBE_FLAG_EXIT_INSTLD))
			skip = 1;
	}
	else if (fork_probe == probe)
	{
		if (us_proc_probes & US_PROC_FORK_INSTLD)
			/*
			 * Uninstall probes only if fork
			 * creates process (not thread).
			 */
			if (!(arg1 & CLONE_VM)) {
				/*
				 * TODO: call fork specific
				 * *_probe_pre_code() function
				 */
				do_exit_probe_pre_code();
			}
		if (!(probes_flags & PROBE_FLAG_FORK_INSTLD))
			skip = 1;
	}
	else if (exec_probe == probe)
	{
		if (us_proc_probes & US_PROC_EXEC_INSTLD)
			/*
			 * FIXME: This is not a good choice to call do_exit_probe_pre_code()
			 * here.  The function should have more common name explaining that
			 * we deinstall all the user space instrumentation from this task.
			 */
			do_exit_probe_pre_code ();
		if (!(probes_flags & PROBE_FLAG_EXEC_INSTLD))
			skip = 1;
	}

	if (!skip)
		pack_event_info (KS_PROBE_ID, RECORD_ENTRY, "pxxxxxx", probe->addr, arg1, arg2, arg3, arg4, arg5, arg6);
	jprobe_return ();
}

int
def_retprobe_event_handler (struct kretprobe_instance *pi, struct pt_regs *regs, kernel_probe_t * probe)
{
	int skip = 0;

	if (pf_probe == probe)
	{
		if (us_proc_probes & US_PROC_PF_INSTLD)
			do_page_fault_ret_pre_code ();
		if (!(probes_flags & PROBE_FLAG_PF_INSTLD))
			skip = 1;
	}
	if (fork_probe == probe)
	{
		/*
		 * Because we uninstall probes before fork new process
		 * there is possibility of a situation with
		 * unhandled events before we put probe.
		 */
		if (us_proc_probes & US_PROC_FORK_INSTLD){
			/*
			 * TODO: call fork specific *_ret_pre_code() function
			 */
			do_page_fault_ret_pre_code();
		}
		if (!(probes_flags & PROBE_FLAG_FORK_INSTLD))
			skip = 1;
	}
	else if (exit_probe == probe)
	{
		if (!(probes_flags & PROBE_FLAG_EXIT_INSTLD))
			skip = 1;
	}

	if (!skip)
		pack_event_info (KS_PROBE_ID, RECORD_RET, "p", probe->addr);
	return 0;
}

/* This is a callback that is called by module 'inperfa_handlers'
 * in order to register user defined handlers */
void install_user_handlers(void)
{
	kernel_probe_t *probe;
	struct hlist_node *node;
	unsigned long pre_handler_addr, jp_handler_addr, rp_handler_addr;

	/* We must perform this lookup whenever this function is called
	 * because the addresses of find_*_handler functions may differ. */
	// MCPP inperfa_handlers removed
	unsigned long (*find_jp_handler)(unsigned long) =
	// MCPP inperfa_handlers removed
		(unsigned long (*)(unsigned long))lookup_name("find_jp_handler");
	unsigned long (*find_rp_handler)(unsigned long) =
			(unsigned long (*)(unsigned long))lookup_name("find_rp_handler");
	unsigned long (*find_pre_handler)(unsigned long) =
			(unsigned long (*)(unsigned long))lookup_name("find_pre_handler");
	hlist_for_each_entry_rcu (probe, node, &kernel_probes, hlist) {
		if(find_pre_handler)
		{
			pre_handler_addr = find_pre_handler(probe->addr);
			if (find_pre_handler != 0) {
				DPRINTF("Added user pre handler for 0x%lx: 0x%lx",
						probe->addr, find_pre_handler);
				probe->jprobe.pre_entry = (kprobe_pre_entry_handler_t)pre_handler_addr;
			}
		}
		jp_handler_addr = find_jp_handler(probe->addr);
		if (jp_handler_addr != 0) {
			DPRINTF("Added user jp handler for 0x%lx: 0x%lx",
					probe->addr, jp_handler_addr);
			probe->jprobe.entry = (kprobe_opcode_t *)jp_handler_addr;
		}
		rp_handler_addr = find_rp_handler(probe->addr);
		if (rp_handler_addr != 0)
			probe->retprobe.handler = (kretprobe_handler_t)rp_handler_addr;
	}
}
EXPORT_SYMBOL_GPL(install_user_handlers);

void uninstall_user_handlers(void)
{
	kernel_probe_t *probe;
	struct hlist_node *node;

	hlist_for_each_entry_rcu (probe, node, &kernel_probes, hlist) {
		DPRINTF("Removed user jp handler for 0x%lx", probe->addr);
		probe->jprobe.pre_entry = (kprobe_pre_entry_handler_t)def_jprobe_event_pre_handler;
		probe->jprobe.entry = (kprobe_opcode_t *)def_jprobe_event_handler;
		probe->retprobe.handler = (kretprobe_handler_t)def_retprobe_event_handler;
	}
}
EXPORT_SYMBOL_GPL(uninstall_user_handlers);

int is_pf_installed_by_user(void)
{
	return (probes_flags & PROBE_FLAG_PF_INSTLD) ? 1: 0;
}
EXPORT_SYMBOL_GPL(is_pf_installed_by_user);
