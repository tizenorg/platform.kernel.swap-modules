#include <linux/slab.h>
#include "msg_parser.h"
#include "msg_buf.h"


static int str_to_u32(const char* str, u32 *val)
{
	u32 result;
	if(!str || !*str)
		return -EINVAL;

	for (result = 0 ; *str; ++str) {
		if (*str < '0' || *str> '9')
			return -EINVAL;

		result = result * 10 + (*str - '0');
	}

	*val = result;

	return 0;
}





/* ============================================================================
 * ==                               APP_INFO                                 ==
 * ============================================================================
 */
struct app_info_data *create_app_info(struct msg_buf *mb)
{
	int ret;
	struct app_info_data *ai;
	u32 app_type;
	char *ta_id, *exec_path;

	ret = get_u32(mb, &app_type);
	if (ret)
		return NULL;

	ret = get_string(mb, &ta_id);
	if (ret)
		return NULL;

	ret = get_string(mb, &exec_path);
	if (ret)
		goto free_ta_id;

	ai = kmalloc(sizeof(*ai), GFP_KERNEL);
	if (ai == NULL)
		goto free_exec_path;

	switch (app_type) {
	case AT_TIZEN_NATIVE_APP:
	case AT_COMMON_EXEC:
		ai->at_data = ta_id;
		break;
	case AT_PID: {
		u32 pid;
		ret = str_to_u32(ta_id, &pid);
		if (ret)
			goto free_ai;

		ai->at_data = (void *)pid;
		break;
	}
	default:
		ret = -EINVAL;
		goto free_ai;
	}

	ai->app_type = (enum APP_TYPE)app_type;
	ai->exec_path = exec_path;

	return ai;

free_ai:
	kfree(ai);

free_exec_path:
	put_strung(exec_path);

free_ta_id:
	put_strung(ta_id);

	return NULL;
}

void destroy_app_info(struct app_info_data *ai)
{
	switch (ai->app_type) {
	case AT_TIZEN_NATIVE_APP:
	case AT_COMMON_EXEC:
		put_strung(ai->at_data);
		break;

	case AT_PID:
		break;

	default:
		printk("### BUG()\n");
		break;
	}

	put_strung(ai->exec_path);
	kfree(ai);
}





/* ============================================================================
 * ==                                CONFIG                                  ==
 * ============================================================================
 */
struct conf_data *create_conf_data(struct msg_buf *mb)
{
	struct conf_data *conf;
	u64 uf;
	u32 stp, dmp;

	if (get_u64(mb, &uf))
		return NULL;

	if (get_u32(mb, &stp))
		return NULL;

	if (get_u32(mb, &dmp))
		return NULL;

	conf = kmalloc(sizeof(*conf), GFP_KERNEL);
	if (conf == NULL)
		return NULL;

	conf->use_features = uf;
	conf->sys_trace_period = stp;
	conf->data_msg_period = dmp;

	return conf;
}

void destroy_conf_data(struct conf_data *conf)
{
	kfree(conf);
}





/* ============================================================================
 * ==                               FUNC_INST                                ==
 * ============================================================================
 */
struct func_inst_data *create_func_inst_data(struct msg_buf *mb)
{
	struct func_inst_data *fi;
	u64 addr;
	char *args;

	if (get_u64(mb, &addr))
		return NULL;

	if (get_string(mb, &args))
		return NULL;

	fi = kmalloc(sizeof(*fi), GFP_KERNEL);
	if (fi == NULL) {
		put_strung(args);
		return NULL;
	}

	fi->addr = addr;
	fi->args = args;

	return fi;
}

void destroy_func_inst_data(struct func_inst_data *fi)
{
	put_strung(fi->args);
	kfree(fi);
}





/* ============================================================================
 * ==                               LIB_INST                                 ==
 * ============================================================================
 */
struct lib_inst_data *create_lib_inst_data(struct msg_buf *mb)
{
	struct lib_inst_data *li;
	struct func_inst_data *fi;
	char *path;
	u32 cnt, j, i = 0;

	if (get_string(mb, &path))
		return NULL;

	if (get_u32(mb, &cnt))
		return NULL;

	if (remained_mb(mb) / MIN_SIZE_FUNC_INST < cnt)
		return NULL;

	li = kmalloc(sizeof(*li), GFP_KERNEL);
	if (li)
		goto free_path;

	li->func = kmalloc(sizeof(struct func_inst_data *) * cnt, GFP_KERNEL);
	if (li->cnt_func)
		goto free_li;

	for (i = 0; i < cnt; ++i) {
		fi = create_func_inst_data(mb);
		if (fi == NULL)
			goto free_func;

		li->func[i] = fi;
	}

	li->path = path;
	li->cnt_func = cnt;

	return li;

free_func:
	for (j = 0; j < i; ++j)
		destroy_func_inst_data(li->func[j]);
	kfree(li->func);

free_li:
	kfree(li);

free_path:
	put_strung(path);

	return NULL;
}

void destroy_lib_inst_data(struct lib_inst_data *li)
{
	int i;

	put_strung(li->path);

	for (i = 0; i < li->cnt_func; ++i)
		destroy_func_inst_data(li->func[i]);

	kfree(li->func);
	kfree(li);
}





/* ============================================================================
 * ==                               APP_INST                                 ==
 * ============================================================================
 */
struct app_inst_data *create_app_inst_data(struct msg_buf *mb)
{
	struct app_inst_data *app_inst;
	struct app_info_data *app_info;
	struct func_inst_data *func;
	struct lib_inst_data *lib;
	u32 cnt_func, i_func = 0, cnt_lib, i_lib = 0, i;

	app_info = create_app_info(mb);
	if (app_info == NULL)
		return NULL;

	if (get_u32(mb, &cnt_func))
		goto free_app_info;

	if (remained_mb(mb) / MIN_SIZE_FUNC_INST < cnt_func)
		goto free_app_info;

	app_inst = kmalloc(sizeof(*app_inst), GFP_KERNEL);
	if (app_inst == NULL)
		goto free_app_info;

	app_inst->func = kmalloc(sizeof(struct func_inst_data *) * cnt_func,
				 GFP_KERNEL);
	if (app_inst->func == NULL)
		goto free_app_inst;

	for (i_func = 0; i_func < cnt_func; ++i_func) {
		func = create_func_inst_data(mb);
		if (func == NULL)
			goto free_func;

		app_inst->func[i_func] = func;
	}

	if (get_u32(mb, &cnt_lib))
		goto free_func;

	if (remained_mb(mb) / MIN_SIZE_LIB_INST < cnt_lib)
		goto free_func;

	app_inst->lib = kmalloc(sizeof(struct lib_inst_data *) * cnt_lib,
				GFP_KERNEL);
	if (app_inst->lib == NULL)
		goto free_func;

	for (i_lib = 0; i_lib < cnt_lib; ++i_lib) {
		lib = create_lib_inst_data(mb);
		if (lib == NULL)
			goto free_lib;

		app_inst->lib[i_lib] = lib;
	}

	app_inst->cnt_func = cnt_func;
	app_inst->cnt_lib = cnt_lib;

	return app_inst;

free_lib:
	for (i = 0; i < i_lib; ++i)
		destroy_lib_inst_data(app_inst->lib[i]);
	kfree(app_inst->lib);

free_func:
	for (i = 0; i < i_func; ++i)
		destroy_func_inst_data(app_inst->func[i]);
	kfree(app_inst->func);

free_app_inst:
	kfree(app_inst);

free_app_info:
	destroy_app_info(app_info);

	return NULL;
}

void destroy_app_inst_data(struct app_inst_data *ai)
{
	int i;

	for (i = 0; i < ai->cnt_lib; ++i)
		destroy_lib_inst_data(ai->lib[i]);
	kfree(ai->lib);

	for (i = 0; i < ai->cnt_func; ++i)
		destroy_func_inst_data(ai->func[i]);
	kfree(ai->func);

	destroy_app_info(ai->app_info);
	kfree(ai);
}





/* ============================================================================
 * ==                                US_INST                                 ==
 * ============================================================================
 */
struct us_inst_data *create_us_inst_data(struct msg_buf *mb)
{
	struct us_inst_data *ui;
	struct app_inst_data *ai;
	u32 cnt, j, i = 0;

	if (get_u32(mb, &cnt))
		return NULL;

	if (remained_mb(mb) / MIN_SIZE_APP_INST < cnt)
		return NULL;

	ui = kmalloc(sizeof(struct us_inst_data), GFP_KERNEL);
	if (ui == NULL)
		return NULL;

	ui->app_inst = kmalloc(sizeof(struct app_inst_data *) * cnt,
			       GFP_KERNEL);
	if (ui->app_inst == NULL)
		goto free_ui;

	for (i = 0; i < cnt; ++i) {
		ai = create_app_inst_data(mb);
		if (ai == NULL)
			goto free_app_inst;

		ui->app_inst[i] = ai;
	}

	ui->cnt = cnt;

	return ui;

free_app_inst:
	for (j = 0; j < i; ++j)
		destroy_app_inst_data(ui->app_inst[j]);
	kfree(ui->app_inst);

free_ui:
	kfree(ui);

	return NULL;
}

void destroy_us_inst_data(struct us_inst_data *ui)
{
	int i;

	for (i = 0; i < ui->cnt; ++i)
		destroy_app_inst_data(ui->app_inst[i]);

	kfree(ui->app_inst);
	kfree(ui);
}
