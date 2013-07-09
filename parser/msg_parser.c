#include <linux/slab.h>
#include "msg_parser.h"
#include "msg_buf.h"
#include "parser_defs.h"


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
	if (ret) {
		print_err("failed to read target application type\n");
		return NULL;
	}

	ret = get_string(mb, &ta_id);
	if (ret) {
		print_err("failed to read target application ID\n");
		return NULL;
	}

	ret = get_string(mb, &exec_path);
	if (ret) {
		print_err("failed to read executable path\n");
		goto free_ta_id;
	}

	ai = kmalloc(sizeof(*ai), GFP_KERNEL);
	if (ai == NULL) {
		print_err("out of memory\n");
		goto free_exec_path;
	}

	switch (app_type) {
	case AT_TIZEN_NATIVE_APP:
	case AT_COMMON_EXEC:
		ai->tgid = 0;
		break;
	case AT_PID: {
		u32 tgid;
		ret = str_to_u32(ta_id, &tgid);
		if (ret) {
			print_err("converting string to PID, str='%s'\n", ta_id);
			goto free_ai;
		}

		ai->tgid = tgid;
		break;
	}
	default:
		print_err("wrong application type(%u)\n", app_type);
		ret = -EINVAL;
		goto free_ai;
	}

	ai->app_type = (enum APP_TYPE)app_type;
	ai->exec_path = exec_path;

	put_strung(ta_id);

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

	if (get_u64(mb, &uf)) {
		print_err("failed to read use_features\n");
		return NULL;
	}

	if (get_u32(mb, &stp)) {
		print_err("failed to read sys trace period\n");
		return NULL;
	}

	if (get_u32(mb, &dmp)) {
		print_err("failed to read data message period\n");
		return NULL;
	}

	conf = kmalloc(sizeof(*conf), GFP_KERNEL);
	if (conf == NULL) {
		print_err("out of memory\n");
		return NULL;
	}

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

	if (get_u64(mb, &addr)) {
		print_err("failed to read data function address\n");
		return NULL;
	}

	if (get_string(mb, &args)) {
		print_err("failed to read data function arguments\n");
		return NULL;
	}

	fi = kmalloc(sizeof(*fi), GFP_KERNEL);
	if (fi == NULL) {
		print_err("out of memory\n");
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

	if (get_string(mb, &path)) {
		print_err("failed to read path of binary\n");
		return NULL;
	}

	if (get_u32(mb, &cnt)) {
		print_err("failed to read count of functions\n");
		return NULL;
	}

	if (remained_mb(mb) / MIN_SIZE_FUNC_INST < cnt) {
		print_err("to match count of functions(%u)\n", cnt);
		return NULL;
	}

	li = kmalloc(sizeof(*li), GFP_KERNEL);
	if (li == NULL)
	if (li == NULL) {
		print_err("out of memory\n");
		goto free_path;
	}

	li->func = kmalloc(sizeof(struct func_inst_data *) * cnt, GFP_KERNEL);
	if (li->func == NULL)
	if (li->func == NULL) {
		print_err("out of memory\n");
		goto free_li;
	}

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

	if (get_u32(mb, &cnt_func)) {
		print_err("failed to read count of functions\n");
		goto free_app_info;
	}

	if (remained_mb(mb) / MIN_SIZE_FUNC_INST < cnt_func) {
		print_err("to match count of functions(%u)\n", cnt_func);
		goto free_app_info;
	}

	app_inst = kmalloc(sizeof(*app_inst), GFP_KERNEL);
	if (app_inst == NULL) {
		print_err("out of memory\n");
		goto free_app_info;
	}

	app_inst->func = kmalloc(sizeof(struct func_inst_data *) * cnt_func,
				 GFP_KERNEL);
	if (app_inst->func == NULL) {
		print_err("out of memory\n");
		goto free_app_inst;
	}

	for (i_func = 0; i_func < cnt_func; ++i_func) {
		func = create_func_inst_data(mb);
		if (func == NULL)
			goto free_func;

		app_inst->func[i_func] = func;
	}

	if (get_u32(mb, &cnt_lib)) {
		print_err("failed to read count of libraries\n");
		goto free_func;
	}

	if (remained_mb(mb) / MIN_SIZE_LIB_INST < cnt_lib) {
		print_err("to match count of libraries(%u)\n", cnt_lib);
		goto free_func;
	}

	app_inst->lib = kmalloc(sizeof(struct lib_inst_data *) * cnt_lib,
				GFP_KERNEL);
	if (app_inst->lib == NULL) {
		print_err("out of memory\n");
		goto free_func;
	}

	for (i_lib = 0; i_lib < cnt_lib; ++i_lib) {
		lib = create_lib_inst_data(mb);
		if (lib == NULL)
			goto free_lib;

		app_inst->lib[i_lib] = lib;
	}

	app_inst->app_info = app_info;
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

	if (get_u32(mb, &cnt)) {
		print_err("failed to read count of applications\n");
		return NULL;
	}

	if (remained_mb(mb) / MIN_SIZE_APP_INST < cnt) {
		print_err("to match count of applications(%u)\n", cnt);
		return NULL;
	}

	ui = kmalloc(sizeof(struct us_inst_data), GFP_KERNEL);
	if (ui == NULL) {
		print_err("out of memory\n");
		return NULL;
	}

	ui->app_inst = kmalloc(sizeof(struct app_inst_data *) * cnt,
			       GFP_KERNEL);
	if (ui->app_inst == NULL) {
		print_err("out of memory\n");
		goto free_ui;
	}

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
