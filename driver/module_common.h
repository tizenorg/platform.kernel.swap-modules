#ifndef MODULE_COMMON
#define MODULE_COMMON

typedef unsigned long (*fp_kallsyms_lookup_name_t) (const char *name);

//export by swap_kprobes.ko
extern fp_kallsyms_lookup_name_t lookup_name;

struct handler_map {
    unsigned long func_addr;
    unsigned long jp_handler_addr;
    unsigned long rp_handler_addr;
    char * func_name;
};
#endif
