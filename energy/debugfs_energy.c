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


/* CPU running */
static u64 cpu_numerator = 1;
static u64 cpu_denominator = 1;

static u64 cpu_system(void)
{
	/* TODO: implement */
	return 0;
}

static u64 cpu_apps(void)
{
	/* TODO: implement */
	return 0;
}


/* CPU idle */
static u64 cpu_idle_numerator = 1;
static u64 cpu_idle_denominator = 1;

static u64 cpu_idle_system(void)
{
	/* TODO: implement */
	return 0;
}


/* flash read */
static u64 fr_numerator = 1;
static u64 fr_denominator = 1;

static u64 fr_system(void)
{
	/* TODO: implement */
	return 0;
}

static u64 fr_apps(void)
{
	/* TODO: implement */
	return 0;
}


/* flash write */
static u64 fw_numerator = 1;
static u64 fw_denominator = 1;

static u64 fw_system(void)
{
	/* TODO: implement */
	return 0;
}

static u64 fw_apps(void)
{
	/* TODO: implement */
	return 0;
}





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


static int get_func_u64(void *data, u64 *val)
{
	u64 (*func)(void) = data;
	*val = func();
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(fops_get_u64, get_func_u64, NULL, "%llu\n");


struct param_data {
	char *name;
	u64 *numerator;
	u64 *denominator;
	u64 (*system)(void);
	u64 (*apps)(void);
};

static struct dentry *create_parameter(struct dentry *parent,
				       struct param_data *param)
{
	struct dentry *name, *num, *den, *system, *apps;

	name = debugfs_create_dir(param->name, parent);
	if (name == NULL)
		return NULL;

	num = debugfs_create_u64("numerator", 0600, name, param->numerator);
	if (num == NULL)
		goto rm_name;

	den = debugfs_create_file("denominator", 0600, name,
				  param->denominator,
				  &fops_denominator);
	if (den == NULL)
		goto rm_numerator;

	system = debugfs_create_file("system", 0600, name, param->system,
				     &fops_get_u64);
	if (system == NULL)
		goto rm_denominator;

	if (param->apps) {
		apps = debugfs_create_file("apps", 0600, name, param->apps,
					   &fops_get_u64);
		if (apps == NULL)
			goto rm_system;
	}

	return name;

rm_system:
	debugfs_remove(system);
rm_denominator:
	debugfs_remove(den);
rm_numerator:
	debugfs_remove(num);
rm_name:
	debugfs_remove(name);

	return NULL;
}

struct param_data parameters[] = {
	{
		.name = "cpu_running",
		.numerator = &cpu_numerator,
		.denominator = &cpu_denominator,
		.system = cpu_system,
		.apps = cpu_apps
	},
	{
		.name = "cpu_idle",
		.numerator = &cpu_idle_numerator,
		.denominator = &cpu_idle_denominator,
		.system = cpu_idle_system,
		.apps = NULL
	},
	{
		.name = "flash_read",
		.numerator = &fr_numerator,
		.denominator = &fr_denominator,
		.system = fr_system,
		.apps = fr_apps
	},
	{
		.name = "flash_write",
		.numerator = &fw_numerator,
		.denominator = &fw_denominator,
		.system = fw_system,
		.apps = fw_apps
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
		dentry = create_parameter(energy_dir, &parameters[i]);
		if (dentry == NULL)
			goto fail;
	}

	return 0;

fail:
	exit_debugfs_energy();
	return -ENOMEM;
}
