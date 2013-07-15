/*
 *  SWAP kernel features
 *  modules/ks_features/ks_features.h
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
 * 2013	 Vyacheslav Cherkashin: SWAP ks_features implement
 *
 */


#ifndef _KS_FEATURES_H
#define _KS_FEATURES_H

enum feature_id {
	FID_FILE = 1,
	FID_IPC = 2,
	FID_PROCESS = 3,
	FID_SIGNAL = 4,
	FID_NET = 5,
	FID_DESC = 6,
	FID_SWITCH = 7
};

int set_feature(enum feature_id id);
int unset_feature(enum feature_id id);

/* debug */
void print_features(void);
void print_all_syscall(void);
/* debug */

#endif /*  _KS_FEATURES_H */
