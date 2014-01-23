/*
 *  SWAP device driver
 *  modules/driver/app_manage.h
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
 * 2014	 Alexander Aksenov <a.aksenov@samsung.com>: Driver user<-> kernel
 *                                                  connect implement
 *
 */

#ifndef __APP_MANAGE_H__
#define __APP_MANAGE_H__

#include "us_interaction.h"
#include "us_interaction_msg.h"

static inline int app_manage_pause_apps(void)
{
	enum us_interaction_k2u_msg_t us_int_msg = US_INT_PAUSE_APPS;

	return us_interaction_send_msg(&us_int_msg, sizeof(us_int_msg));
}

static inline int app_manage_cont_apps(void)
{
	enum us_interaction_k2u_msg_t us_int_msg = US_INT_CONT_APPS;

	return us_interaction_send_msg(&us_int_msg, sizeof(us_int_msg));
}

#endif /* __APP_MANAGE_H__ */
