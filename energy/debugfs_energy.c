/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  energy/debugfs_energy.c
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
 * Copyright (C) Samsung Electronics, 2013
 *
 * 2013         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/fs.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <driver/swap_debugfs.h>


/* CPU */
static u64 cpu_numerator = 1;
static u64 cpu_denominator = 1;

/* flash read */
static u64 fr_numerator = 1;
static u64 fr_denominator = 1;

/* flash write */
static u64 fw_numerator = 1;
static u64 fw_denominator = 1;





/* ============================================================================
 * ===                             PARAMETERS                               ===
 * ============================================================================
 */
static int denominator_set(void *data, u64 val)
{
	if (val == 0)
		return -EINVAL;

	*(u64 *)data = val;
	return 0;
}

static int denominator_get(void *data, u64 *val)
{
	*val = *(u64 *)data;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(fops_denominator, denominator_get, \
			denominator_set, "%llu\n");

static int create_fraction(struct dentry *parent,
			   u64 *numerator, u64 *denominator)
{
	struct dentry *num, *den;

	num = debugfs_create_u64("numerator", 0600, parent, numerator);
	if (num == NULL)
		return -ENOMEM;

	den = debugfs_create_file("denominator", 0600, parent, denominator,
				  &fops_denominator);
	if (den == NULL) {
		debugfs_remove(num);
		return -ENOMEM;
	}

	return 0;
}

static struct dentry *create_parameter(struct dentry *parent, const char *name,
				       u64 *numerator, u64 *denominator)
{
	struct dentry *dentry;

	dentry = debugfs_create_dir(name, parent);
	if (dentry) {
		int err;

		err = create_fraction(dentry, &cpu_numerator,
				      &cpu_denominator);

		if (err) {
			debugfs_remove(dentry);
			dentry = NULL;
		}
	}

	return dentry;
}

struct param_data {
	char *name;
	u64 *numerator;
	u64 *denominator;
};

struct param_data parameters[] = {
	{
		.name = "CPU",
		.numerator = &cpu_numerator,
		.denominator = &cpu_denominator
	},
	{
		.name = "flash_read",
		.numerator = &fr_numerator,
		.denominator = &fr_denominator
	},
	{
		.name = "flash_write",
		.numerator = &fw_numerator,
		.denominator = &fw_denominator
	}
};

enum {
	parameters_cnt = sizeof(parameters) / sizeof(struct param_data)
};





/* ============================================================================
 * ===                              INIT/EXIT                               ===
 * ============================================================================
 */
static struct dentry *energy_dir = NULL;

void exit_debugfs_energy(void)
{
	if (energy_dir)
		debugfs_remove_recursive(energy_dir);

	energy_dir = NULL;
}

int init_debugfs_energy(void)
{
	int i;
	struct dentry *swap_dir, *dentry;

	swap_dir = get_swap_debugfs_dir();
	if (swap_dir == NULL)
		return -ENOENT;

	energy_dir = debugfs_create_dir("energy", swap_dir);
	if (energy_dir == NULL)
		return -ENOMEM;

	for (i = 0; i < parameters_cnt; ++i) {
		dentry = create_parameter(energy_dir, parameters[i].name,
					  parameters[i].numerator,
					  parameters[i].denominator);
		if (dentry == NULL)
			goto fail;
	}

	return 0;

fail:
	exit_debugfs_energy();
	return -ENOMEM;
}
