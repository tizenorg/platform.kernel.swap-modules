////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           handlers_core.h
//
//      DESCRIPTION:
//      This file is C source for SWAP.
//
//      SEE ALSO:       storage.c
//      AUTHOR:         S. Andreev
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2012.07.25
//      VERSION:        1.0
//      REVISION DATE:  2012.07.25
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(__HANDLERS_CORE_H__)
#define __HANDLERS_CORE_H__

#include <linux/module.h>
#include <linux/list.h>
#include <linux/spinlock.h>

// multiple handlers stuff
struct dbi_modules_handlers {
	struct list_head	modules_handlers;
	spinlock_t		lock;
};

struct dbi_modules_handlers_info {
	struct module		*dbi_module;
	struct handler_map	*dbi_handlers;
	int			dbi_nr_handlers;
	struct list_head	dbi_list_head;
	void *			dbi_module_callback_start;
	void *			dbi_module_callback_stop;
	int			dbi_module_priority_start;
	int			dbi_module_priority_stop;
};

extern int dbi_register_handlers_module(struct dbi_modules_handlers_info *dbi_mhi);
extern int dbi_unregister_handlers_module(struct dbi_modules_handlers_info *dbi_mhi);
//unsigned long get_dbi_modules_handlers(void);

#endif /* !defined(__HANDLERS_CORE_H__) */
