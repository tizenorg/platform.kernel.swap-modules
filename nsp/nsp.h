#ifndef _NSP_H
#define _NSP_H

/*
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
 * Copyright (C) Samsung Electronics, 2015
 *
 * 2015         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


enum offset_t {
	OS_CREATE,
	OS_RESET
};

enum nsp_stat {
	NS_OFF,
	NS_ON
};


int nsp_init(void);
void nsp_exit(void);

int nsp_set_offset(enum offset_t os, unsigned long offset);
int nsp_set_lpad_info(bool is_process_pool, const char *path,
		      unsigned long dlopen, unsigned long dlsym);
int nsp_set_appcore_info(const char *path, unsigned long appcore_efl_main);

int nsp_set_stat(enum nsp_stat st);
enum nsp_stat nsp_get_stat(void);

int nsp_add(bool is_process_pool, const char *app_path);
int nsp_rm(const char *app_path);
int nsp_rm_all(void);


#endif /* _NSP_H */
