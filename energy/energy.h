#ifndef _ENERGY_H
#define _ENERGY_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  energy/energy.h
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


#include <linux/types.h>


enum parameter_energy {
	PE_TIME_IDLE,
	PE_TIME_SYSTEM,
	PE_TIME_APPS,
	PE_READ_SYSTEM,
	PE_WRITE_SYSTEM,
	PE_READ_APPS,
	PE_WRITE_APPS
};


int energy_init(void);
void energy_uninit(void);

int set_energy(void);
int unset_energy(void);

int get_parameter_energy(enum parameter_energy pe, void *buf, size_t sz);

#endif /* _ENERGY_H */
