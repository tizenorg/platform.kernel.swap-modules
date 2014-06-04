/*
 *  SWAP uprobe manager
 *  modules/us_manager/probes/preload_probe.h
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
 * 2014	 Alexander Aksenov: FBI implement
 *
 */

#ifndef __PRELOAD_PROBE_H__
#define __PRELOAD_PROBE_H__

/* Probe type, specifies when probe should be ran. */
enum preload_probe_type_t {
	SWAP_PRELOAD_INTERNAL_CALL = 0,     /* Run probe only when it is called from
					       target binaries. */
	SWAP_PRELOAD_ALWAYS = 1,            /* Run probe always. */
	SWAP_PRELOAD_DISABLE_HANDLING = 2   /* Disable handlers execution. */
};

/* Preload probe info. */
struct preload_info {
	unsigned long handler;              /* Handler offset in probe library. */
	enum preload_probe_type_t type;     /* Preload probe type. */
};

/* Get caller probe info */
struct get_caller_info {
};

/* Get call type probe info */
struct get_call_type_info {
};

int register_preload_probes(void);
void unregister_preload_probes(void);

#endif /* __URETPROBE_H__ */
