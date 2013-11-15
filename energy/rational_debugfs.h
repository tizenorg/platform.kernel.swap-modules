#ifndef _RATIONAL_DEBUGFS_H
#define _RATIONAL_DEBUGFS_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  energy/rational_debugfs.h
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


struct rational {
	u64 num;
	u64 denom;
};


#define DEFINE_RATIONAL(rational_name)		\
	struct rational rational_name = {	\
		.num = 1,			\
		.denom = 1			\
	}


struct dentry;


int create_rational_files(struct dentry *parent, struct rational *r,
			  const char *num_name, const char *denom_name);


#endif /* _RATIONAL_DEBUGFS_H */
