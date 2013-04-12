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
#include <ksyms.h>
#include <dbi_kprobes_deps.h>
#include "module.h"
#include "probes_manager.h"

int
probes_manager_init (void)
{
	int ret;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
	spin_lock_init(&ec_spinlock);
	spin_lock_init(&ec_probe_spinlock);
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */

	ret = init_helper();
	if (ret)
		return ret;

	return storage_init ();
}

void
probes_manager_down (void)
{
	detach_selected_probes ();
	uninit_helper();
	storage_down ();
}

static int register_kernel_probe(kernel_probe_t *p)
{
	int ret;

	/* register jprobe */
	ret = dbi_register_jprobe(&p->jprobe);
	if (ret) {
		EPRINTF("dbi_register_jprobe(0x%lx) failure %d", p->addr, ret);
		return ret;
	};

	/* register kretprobe */
	ret = dbi_register_kretprobe(&p->retprobe);
	if (ret) {
		EPRINTF("dbi_register_kretprobe(0x%lx) failure %d",
			p->addr, ret);

		dbi_unregister_jprobe(&p->jprobe);
		return ret;
	}

	return 0;
}

static int unregister_kernel_probe(kernel_probe_t *p)
{
	dbi_unregister_kretprobe(&p->retprobe);
	dbi_unregister_jprobe(&p->jprobe);

	return 0;
}

int
attach_selected_probes (void)
{
	int result = 0;
	int partial_result = 0;
	kernel_probe_t *p;
	struct hlist_node *node;

	swap_hlist_for_each_entry_rcu (p, node, &kernel_probes, hlist)
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

	swap_hlist_for_each_entry_rcu (p, node, &kernel_probes, hlist)
		unregister_kernel_probe (p);
	swap_hlist_for_each_entry_rcu (p, node, &otg_kernel_probes, hlist) {
		unregister_kernel_probe(p);
	}

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

	result = add_probe_to_list (addr, pprobe);

	return result;
}

int reset_probes(void)
{
	struct hlist_node *node, *tnode;
	kernel_probe_t *p;

	swap_hlist_for_each_entry_safe (p, node, tnode, &kernel_probes, hlist) {
		hlist_del(node);
		kfree(p);
	}

	swap_hlist_for_each_entry_safe (p, node, tnode, &otg_kernel_probes, hlist) {
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

	result = remove_probe_from_list (addr);

	return result;
}

static DEFINE_PER_CPU(kernel_probe_t *, gpKernProbe) = NULL;

unsigned long
def_jprobe_event_pre_handler (kernel_probe_t * probe, struct pt_regs *regs)
{
	__get_cpu_var (gpKernProbe) = probe;

	return 0;
}

void
def_jprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	//static int nCount;
	kernel_probe_t *probe = __get_cpu_var(gpKernProbe);

	pack_event_info(KS_PROBE_ID, RECORD_ENTRY, "pxxxxxx", probe->addr, arg1, arg2, arg3, arg4, arg5, arg6);
	dbi_jprobe_return ();
}

int
def_retprobe_event_handler (struct kretprobe_instance *pi, struct pt_regs *regs, kernel_probe_t * probe)
{
	int ret_val;

	ret_val = regs_return_value(regs);
	pack_event_info(KS_PROBE_ID, RECORD_RET, "pd", probe->addr, ret_val);

	return 0;
}

int install_kern_otg_probe(unsigned long addr,
			   unsigned long pre_handler,
			   unsigned long jp_handler,
			   unsigned long rp_handler)
{
	kernel_probe_t *new_probe = NULL;
	kernel_probe_t *probe;
	int ret = 0;

	probe = find_probe(addr);
	if (probe) {
		/* It is not a problem if we have already registered
		   this probe before */
		return 0;
	}

	new_probe = kmalloc(sizeof (kernel_probe_t), GFP_ATOMIC);
	if (!new_probe) {
		EPRINTF("No memory for new probe");
		return -1;
	}
	memset(new_probe, 0, sizeof(kernel_probe_t));

	new_probe->addr = addr;
	new_probe->jprobe.kp.addr = new_probe->retprobe.kp.addr = (kprobe_opcode_t *)addr;
	new_probe->jprobe.priv_arg = new_probe->retprobe.priv_arg = new_probe;

	if (pre_handler) {
		new_probe->jprobe.pre_entry =
			(kprobe_pre_entry_handler_t)
			pre_handler;
	} else {
		new_probe->jprobe.pre_entry =
			(kprobe_pre_entry_handler_t)
			def_jprobe_event_pre_handler;
	}

	if (jp_handler) {
		new_probe->jprobe.entry = (kprobe_opcode_t *)jp_handler;
	} else {
		new_probe->jprobe.entry =
			(kprobe_opcode_t *)
			def_jprobe_event_handler;
	}

	if (rp_handler) {
		new_probe->retprobe.handler = (kretprobe_handler_t)rp_handler;
	} else {
		new_probe->retprobe.handler =
			(kretprobe_handler_t)
			def_retprobe_event_handler;
	}

	INIT_HLIST_NODE (&new_probe->hlist);
	hlist_add_head_rcu (&new_probe->hlist, &kernel_probes);

	ret = register_kernel_probe(new_probe);
	if (ret) {
		EPRINTF("Cannot set kernel probe at addr %lx", addr);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(install_kern_otg_probe);
