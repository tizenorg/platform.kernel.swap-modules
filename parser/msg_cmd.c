#include <linux/errno.h>
#include "msg_parser.h"
#include "msg_buf.h"
#include "features.h"
#include "parser_defs.h"
#include "us_inst.h"

static int set_app_info(struct app_info_data *app_info)
{
	return 0;
}

static int set_config(struct conf_data *conf)
{
	int ret;

	ret = set_features(conf);

	return ret;
}

int msg_keep_alive(struct msg_buf *mb)
{
	if (!is_end_mb(mb)) {
		print_err("to long message, remained=%u", remained_mb(mb));
		return -EINVAL;
	}

	return 0;
}

int msg_start(struct msg_buf *mb)
{
	int ret = 0;
	struct app_info_data *app_info;
	struct conf_data *conf;
	struct us_inst_data *us_inst;

	app_info = create_app_info(mb);
	if (app_info == NULL)
		return -EINVAL;

	conf = create_conf_data(mb);
	if (conf == NULL) {
		ret = -EINVAL;
		goto free_app_info;
	}

	us_inst = create_us_inst_data(mb);
	if (us_inst == NULL) {
		ret = -EINVAL;
		goto free_conf;
	}

	if (!is_end_mb(mb)) {
		print_err("to long message, remained=%u", remained_mb(mb));
		ret = -EINVAL;
		goto free_us_inst;
	}

	/* TODO implement the processing */
	ret = set_config(conf);
	if (ret)
		goto free_us_inst;

	ret = mod_us_inst(us_inst, MT_ADD);

free_us_inst:
	destroy_us_inst_data(us_inst);

free_conf:
	destroy_conf_data(conf);

free_app_info:
	destroy_app_info(app_info);

	return ret;
}

int msg_stop(struct msg_buf *mb)
{
	if (!is_end_mb(mb)) {
		print_err("to long message, remained=%u", remained_mb(mb));
		return -EINVAL;
	}

	/* TODO implement the processing */

	return 0;
}

int msg_config(struct msg_buf *mb)
{
	int ret = 0;
	struct conf_data *conf;

	conf = create_conf_data(mb);
	if (conf == NULL)
		return -EINVAL;

	if (!is_end_mb(mb)) {
		print_err("to long message, remained=%u", remained_mb(mb));
		ret = -EINVAL;
		goto free_conf_data;
	}

	/* TODO implement the processing */
	set_config(conf);

free_conf_data:
	destroy_conf_data(conf);

	return ret;
}

int msg_swap_inst_add(struct msg_buf *mb)
{
	int ret = 0;
	struct us_inst_data *us_inst;

	us_inst = create_us_inst_data(mb);
	if (us_inst == NULL) {
		return -EINVAL;
	}

	if (!is_end_mb(mb)) {
		print_err("to long message, remained=%u", remained_mb(mb));
		ret = -EINVAL;
		goto free_us_inst;
	}

	ret = mod_us_inst(us_inst, MT_ADD);

free_us_inst:
	destroy_us_inst_data(us_inst);

	return ret;
}

int msg_swap_inst_remove(struct msg_buf *mb)
{
	int ret = 0;
	struct us_inst_data *us_inst;

	us_inst = create_us_inst_data(mb);
	if (us_inst == NULL) {
		return -EINVAL;
	}

	if (!is_end_mb(mb)) {
		print_err("to long message, remained=%u", remained_mb(mb));
		ret = -EINVAL;
		goto free_us_inst;
	}

	ret = mod_us_inst(us_inst, MT_DEL);

free_us_inst:
	destroy_us_inst_data(us_inst);

	return ret;
}

int init_cmd(void)
{
	int ret;

	ret = init_features();

	return ret;
}

void uninit_cmd(void)
{
	uninit_features();
}
