/* Current protocol versions description */

#include <linux/types.h>

#ifndef __PROTOCOL_DESCRIPTION_H__
#define __PROTOCOL_DESCRIPTION_H__

enum features {
    CPU                 = 0x1,      /* CPU core load, frequency, process load */
    memory              = 0x2,      /* Process size, heap usage, physical memory */
    func_profiling      = 0x4,      /* On/Off the UserSpaceInst */
    mem_allocation      = 0x8,      /* Memory allocation API */
    file_api            = 0x10,     /* File API */
    thread_api          = 0x20,     /* Thread API */
    osp_ui_api          = 0x40,     /* UI API */
    screenshot          = 0x80,     /* Screenshot */
    user_event          = 0x100,    /* Touch, Gesture, Orientation, Key */
    recording           = 0x200,    /* Recording user events */
    syscall_file        = 0x400,    /* File operation syscalls tracing */
    syscall_ipc         = 0x800,    /* IPC syscall tracing */
    syscall_process     = 0x1000,   /* Process syscalls tracing */
    syscall_signal      = 0x2000,   /* Signal syscalls tracing */
    syscall_network     = 0x4000,   /* Network syscalls tracing */
    syscall_desc        = 0x8000,   /* Descriptor syscalls tracing */
    context_switch      = 0x10000,  /* Context switch tracing */
    network_api         = 0x20000,  /* Network API */
    opengl_api          = 0x40000,  /* OpenGL API */
    function_sampling   = 0x80000   /* Function sampling */
};

/* Basic application information */
struct application_information_t {
    u_int32_t t_app_type;
    char *t_app_id;
    char *exec_path;
};

/* Configuration struct */
struct configuration_t {
    u_int64_t use_features;
    u_int32_t sys_trace_period;
    u_int32_t data_msg_period;
};

/* User space instrumentation struct */
struct user_space_inst_t {
    u_int32_t app_count;
    struct application_inst_t *a_inst;
};

/* Application struct */
struct application_inst_t {
    char *app_path;
    u_int32_t func_count;
    struct function_inst_t *f_inst;
    u_int32_t lib_count;
    struct library_inst_t *l_inst;
};

/* Application and library functions to set probes */
struct function_inst_t {
    u_int64_t func_address;
    u_int32_t args_count;
    char *args;
};

/* Library struct */
struct library_inst_t {
    char *lib_path;
    u_int32_t func_count;
    struct function_inst_t *f_inst;
};


#endif /* __PROTOCOL_DESCRIPTION_H__ */
