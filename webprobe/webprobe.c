/**
 * webprobe/webprobe.c
 * @author Ruslan Soloviev
 *
 * @section LICENSE
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
 * @section COPYRIGHT
 *
 * Copyright (C) Samsung Electronics, 2014
 *
 * @section DESCRIPTION
 *
 * Web application profiling
 */


#include <us_manager/us_manager.h>
#include <us_manager/sspt/ip.h>
#include <us_manager/probes/register_probes.h>
#include <writer/swap_writer_module.h>
#include <uprobe/swap_uprobes.h>
#include <parser/msg_cmd.h>
#include <linux/module.h>
#include <linux/slab.h>

static int webprobe_copy(struct probe_info *dest,
			 const struct probe_info *source)
{
	memcpy(dest, source, sizeof(*source));

	return 0;
}

static void webprobe_cleanup(struct probe_info *probe_i)
{
}

static struct uprobe *webprobe_get_uprobe(struct us_ip *ip)
{
	return &ip->retprobe.up;
}

static int webprobe_register_probe(struct us_ip *ip)
{
	return swap_register_uretprobe(&ip->retprobe);
}

static void webprobe_unregister_probe(struct us_ip *ip, int disarm)
{
	__swap_unregister_uretprobe(&ip->retprobe, disarm);
}

static int entry_web_handler(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct uretprobe *rp = ri->rp;

	if (rp && get_quiet() == QT_OFF) {
		struct us_ip *ip = container_of(rp, struct us_ip, retprobe);
		unsigned long addr = (unsigned long)ip->orig_addr;

		entry_web_event(addr, regs);
	}

	return 0;
}

static int exit_web_handler(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct uretprobe *rp = ri->rp;

	if (rp && get_quiet() == QT_OFF) {
		struct us_ip *ip = container_of(rp, struct us_ip, retprobe);
		unsigned long addr = (unsigned long)ip->orig_addr;

		exit_web_event(addr, regs);
	}

	return 0;
}

static int ret_web_handler(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	set_wrt_launcher_port((int)regs_return_value(regs));

	return 0;
}

#define WEB_FUNC_INSPSERVSTART		0
#define WEB_FUNC_WILLEXECUTE		1
#define WEB_FUNC_DIDEXECUTE		2

static void webprobe_init(struct us_ip *ip)
{
	static int fcnt = 0;

	switch(fcnt++) {
	case WEB_FUNC_INSPSERVSTART:
		ip->retprobe.entry_handler = NULL;
		ip->retprobe.handler = ret_web_handler;
		printk("SWAP_WEBPROBE: web function ewk_view_inspector_server_start\n");
		break;
	case WEB_FUNC_WILLEXECUTE:
		/* TODO: use uprobe instead of uretprobe */
		ip->retprobe.entry_handler = entry_web_handler;
		ip->retprobe.handler = NULL;
		printk("SWAP_WEBPROBE: web function willExecute\n");
		break;
	case WEB_FUNC_DIDEXECUTE:
		/* TODO: use uprobe instead of uretprobe */
		ip->retprobe.entry_handler = exit_web_handler;
		ip->retprobe.handler = NULL;
		printk("SWAP_WEBPROBE: web function didExecute\n");
		/* FIXME: probes can be set more than once */
		fcnt = 0;
		break;
	default:
		printk("SWAP_WEBPROBE: web functions more than necessary\n");
	}

	ip->retprobe.maxactive = 0;
}

static void webprobe_uninit(struct us_ip *ip)
{
	webprobe_cleanup(&ip->probe_i);
}


static struct probe_iface webprobe_iface = {
	.init = webprobe_init,
	.uninit = webprobe_uninit,
	.reg = webprobe_register_probe,
	.unreg = webprobe_unregister_probe,
	.get_uprobe = webprobe_get_uprobe,
	.copy = webprobe_copy,
	.cleanup = webprobe_cleanup
};

static int __init webprobe_module_init(void)
{
	return swap_register_probe_type(SWAP_WEBPROBE, &webprobe_iface);
}

static void __exit webprobe_module_exit(void)
{
	swap_unregister_probe_type(SWAP_WEBPROBE);
}

module_init(webprobe_module_init);
module_exit(webprobe_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP webprobe");
MODULE_AUTHOR("Ruslan Soloviev <r.soloviev@samsung.com>");
