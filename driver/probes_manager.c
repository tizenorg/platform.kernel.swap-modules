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

#include <linux/module.h>
#include <ks_manager.h>


int set_kernel_probes(void)
{
	return 0;
}

int unset_kernel_probes(void)
{
	return ksm_unregister_probe_all();
}

int add_probe(unsigned long addr,
	      unsigned long pre_handler,
	      unsigned long jp_handler,
	      unsigned long rp_handler)
{
	return ksm_register_probe(addr, pre_handler, jp_handler, rp_handler);
}

int reset_probes(void)
{
	return 0;
}
