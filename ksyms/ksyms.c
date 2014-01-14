/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/ksyms/ksyms.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) Samsung Electronics, 2014
 *
 * 2014         Alexander Aksenov <a.aksenov@samsung.com>
 *
 */


#include "ksyms.h"
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/percpu.h>

struct symbol_data {
	const char *name;
	size_t len;
	unsigned long addr;
};

static int symbol_cb(void *data, const char *sym, struct module *mod,
		     unsigned long addr)
{
	struct symbol_data *sym_data_p = (struct symbol_data *)data;

	/* We expect that real symbol name should have at least the same length as
	 * symbol name we are looking for. */
	if (strncmp(sym_data_p->name, sym, sym_data_p->len) == 0) {
		sym_data_p->addr = addr;
		/* Return != 0 to stop loop over the symbols */
		return 1;
	}

	return 0;
}

unsigned long swap_ksyms_substr(const char *name)
{
	struct symbol_data sym_data = {
		.name = name,
		.len = strlen(name),
		.addr = 0
	};
	kallsyms_on_each_symbol(symbol_cb, (void *)&sym_data);

	return sym_data.addr;
}
EXPORT_SYMBOL_GPL(swap_ksyms_substr);

int __init swap_ksyms_init(void)
{
	printk("SWAP_KSYMS: Module initialized\n");

	return 0;
}

void __exit swap_ksyms_exit(void)
{
	printk("SWAP_KSYMS: Module uninitialized\n");
}

module_init(swap_ksyms_init);
module_exit(swap_ksyms_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP ksyms module");
MODULE_AUTHOR("Vyacheslav Cherkashin <v.cherkashin@samaung.com>");

