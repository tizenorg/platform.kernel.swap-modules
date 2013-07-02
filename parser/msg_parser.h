#ifndef _MSG_PARSER_H
#define _MSG_PARSER_H

#include <linux/types.h>

struct msg_buf;

enum APP_TYPE {
	AT_TIZEN_NATIVE_APP	= 0x01,
	AT_PID			= 0x02,
	AT_COMMON_EXEC		= 0x03
};

/* Basic application information */
struct app_info_data {
	enum APP_TYPE app_type;
	void *at_data;
	char *exec_path;
};

/* Configuration struct */
struct conf_data {
	u64 use_features;
	u32 sys_trace_period;
	u32 data_msg_period;
};

/* Application and library functions to set probes */
struct func_inst_data {
	u64 addr;
	char *args;
};

/* Library struct */
struct lib_inst_data {
	char *path;
	u32 cnt_func;
	struct func_inst_data **func;
};

/* Application struct */
struct app_inst_data {
	struct app_info_data *app_info;
	u32 cnt_func;
	struct func_inst_data **func;
	u32 cnt_lib;
	struct lib_inst_data **lib;
};

/* User space instrumentation struct */
struct us_inst_data {
	u32 cnt;
	struct app_inst_data **app_inst;
};


struct app_info_data *create_app_info(struct msg_buf *mb);
void destroy_app_info(struct app_info_data *app_info);

struct conf_data *create_conf_data(struct msg_buf *mb);
void destroy_conf_data(struct conf_data *conf);

struct func_inst_data *create_func_inst_data(struct msg_buf *mb);
void destroy_func_inst_data(struct func_inst_data *func_inst);

struct lib_inst_data *create_lib_inst_data(struct msg_buf *mb);
void destroy_lib_inst_data(struct lib_inst_data *lib_inst);

struct app_inst_data *create_app_inst_data(struct msg_buf *mb);
void destroy_app_inst_data(struct app_inst_data *app_inst);

struct us_inst_data *create_us_inst_data(struct msg_buf *mb);
void destroy_us_inst_data(struct us_inst_data *us_inst);

#endif /* _MSG_PARSER_H */
