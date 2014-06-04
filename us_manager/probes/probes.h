/*
 *  SWAP uprobe manager
 *  modules/us_manager/probes/probes.h
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
 * 2014	 Alexander Aksenov: Probes interface implement
 *
 */


#ifndef __PROBES_H__
#define __PROBES_H__

#include <linux/types.h>

#include <preload/preload_probe.h>   /* TODO Remove */
#include <retprobe/retprobe.h>       /* TODO Remove */



/* All probe types. Only us_manager should know about them - it is its own
 * business to install proper probes on proper places.
 */
enum probe_t {
	SWAP_RETPROBE = 0,          /* Retprobe */
	SWAP_PRELOAD_PROBE = 2,     /* Preload probe */
	SWAP_WEBPROBE = 3,          /* Webprobe */
	SWAP_GET_CALLER = 4,        /* Get caller probe. Supports preload */
	SWAP_GET_CALL_TYPE = 5,     /* Get call type probe. Supports preload */
	SWAP_PROBE_MAX_VAL          /* Probes max value. */
};

/* Probe info stuct. It contains the whole information about probe. */
struct probe_info {
	enum probe_t probe_type;
	size_t size;
	/* Union of all SWAP supported probe types */
	union {
		struct retprobe_info rp_i;
		struct preload_info pl_i;
		struct get_caller_info gc_i;
		struct get_call_type_info gct_i;
	};
};

#endif /* __PROBES_H__ */
