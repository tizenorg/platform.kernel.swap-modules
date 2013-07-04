#include <linux/module.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>

#include "parser_defs.h"
#include "msg_buf.h"
#include "msg_cmd.h"

#include <driver_new/device_driver.h>
#include <driver_new/swap_ioctl.h>

enum MSG_ID {
	MSG_KEEP_ALIVE		= 0x0001,
	MSG_START		= 0x0002,
	MSG_STOP		= 0x0003,
	MSG_CONFIG		= 0x0004,
	MSG_SWAP_INST_ADD	= 0x0008,
	MSG_SWAP_INST_REMOVE	= 0x0009
};

struct basic_msg_fmt {
	u32 msg_id;
	u32 len;
} __attribute__((packed));

static int msg_handler(void __user *msg)
{
	int ret;
	u32 size;
	enum MSG_ID msg_id;
	struct msg_buf mb;
	void __user *payload;
	struct basic_msg_fmt bmf;

	ret = copy_from_user(&bmf, (void*)msg, sizeof(bmf));
	if (ret)
		return ret;

	size = bmf.len;
	ret = init_mb(&mb, size);
	if (ret)
		return ret;

	payload = msg + sizeof(bmf);
	if (size) {
		ret = copy_from_user(mb.begin, (void*)payload, size);
		if (ret)
			goto uninit;
	}

	msg_id = bmf.msg_id;
	switch (msg_id) {
	case MSG_KEEP_ALIVE:
		print_parse_debug("MSG_KEEP_ALIVE\n");
		ret = msg_keep_alive(&mb);
		break;
	case MSG_START:
		print_parse_debug("MSG_START\n");
		ret = msg_start(&mb);
		break;
	case MSG_STOP:
		print_parse_debug("MSG_STOP\n");
		ret = msg_stop(&mb);
		break;
	case MSG_CONFIG:
		print_parse_debug("MSG_CONFIG\n");
		ret = msg_config(&mb);
		break;
	case MSG_SWAP_INST_ADD:
		print_parse_debug("MSG_SWAP_INST_ADD\n");
		ret = msg_swap_inst_add(&mb);
		break;
	case MSG_SWAP_INST_REMOVE:
		print_parse_debug("MSG_SWAP_INST_REMOVE\n");
		ret = msg_swap_inst_remove(&mb);
		break;
	default:
		print_err("incorrect message ID [%u]\n", msg_id);
		ret = -EINVAL;
		break;
	}

uninit:
	uninit_mb(&mb);
	return ret;
}

static void register_msg_handler(void)
{
	set_msg_handler(msg_handler);
}

static void unregister_msg_handler(void)
{
	set_msg_handler(NULL);
}

static int __init swap_parser_init(void)
{
	register_msg_handler();

	return 0;
}

static void __exit swap_parser_exit(void)
{
	unregister_msg_handler();
}

module_init(swap_parser_init);
module_exit(swap_parser_exit);

MODULE_LICENSE("GPL");
