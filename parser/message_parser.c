/* Message parser */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <asm/uaccess.h>

#include "message_parser.h"
#include "swap_message_parser_errors.h"
#include "parser_defs.h"


/* Create application_information_t structs */
static struct application_information_t *create_app_info(u_int32_t count)
{
    struct application_information_t *a_info;
    struct application_information_t *current_a_info;
    u_int32_t i;

    /* Alloc memory for application_information_t structs */
    a_info = kmalloc(sizeof(struct application_information_t) * count,
                     GFP_KERNEL);
    if (!a_info)
        return NULL;

    /* Initialization */
    current_a_info = a_info;
    for (i = 0; i < count; i++) {
        current_a_info->t_app_type = 0;
        current_a_info->t_app_id = NULL;
        current_a_info->exec_path = NULL;
        current_a_info++;
    }

    return a_info;
}

/* Create configuration_t structs */
static struct configuration_t *create_configuration(u_int32_t count)
{
    struct configuration_t *c;
    struct configuration_t *current_c;
    u_int32_t i;

    /* Alloc memory for configuration_t structs */
    c = kmalloc(sizeof(struct configuration_t) * count, GFP_KERNEL);
    if (!c)
        return NULL;

    /* Initialization */
    current_c = c;
    for (i = 0; i < count; i++) {
        current_c->use_features = 0;
        current_c->sys_trace_period = 0;
        current_c->data_msg_period = 0;
        current_c++;
    }

    return c;
}

/* Create user_space_inst_t structs */
static struct user_space_inst_t *create_user_space_inst(u_int32_t count)
{
    struct user_space_inst_t *u_s_i;
    struct user_space_inst_t *current_u_s_i;
    u_int32_t i;

    /* Alloc memory for user_space_inst_t structs */
    u_s_i = kmalloc(sizeof(struct user_space_inst_t) * count, GFP_KERNEL);
    if (!u_s_i)
        return NULL;

    /* Structs initialization */
    current_u_s_i = u_s_i;
    for (i = 0; i < count; i++) {
        current_u_s_i->app_count = 0;
        current_u_s_i->a_inst = NULL;
        current_u_s_i++;
    }

    return u_s_i;
}

/* Create application_inst_t structs */
static struct application_inst_t *create_application_inst(u_int32_t count)
{
    struct application_inst_t *a_inst;
    struct application_inst_t *current_a_inst;
    u_int32_t i;

    /* Alloc memory for application_inst_t structs */
    a_inst = kmalloc(sizeof(struct application_inst_t) * count, GFP_KERNEL);
    if (!a_inst)
        return NULL;

    /* Initialization */
    current_a_inst = a_inst;
    for(i = 0; i < count; i++) {
        current_a_inst->app_path = NULL;
        current_a_inst->func_count = 0;
        current_a_inst->f_inst = NULL;
        current_a_inst->lib_count = 0;
        current_a_inst->l_inst = NULL;
        current_a_inst++;}

    return a_inst;
}

/* Create library_inst_t stucts */
static struct library_inst_t *create_library_inst(u_int32_t count)
{
    struct library_inst_t *l_inst;
    struct library_inst_t *current_l_inst;
    u_int32_t i;

    /* Alloc memory for library_inst_t structs */
    l_inst = kmalloc(sizeof(struct library_inst_t) * count, GFP_KERNEL);
    if (!l_inst)
        return NULL;

    /* Initialization */
    current_l_inst = l_inst;
    for (i = 0; i < count; i++) {
        current_l_inst->lib_path = NULL;
        current_l_inst->func_count = 0;
        current_l_inst->f_inst = NULL;
        current_l_inst++;
    }

    return l_inst;
}

/* Create function_inst_t structs */
static struct function_inst_t *create_function_inst(u_int32_t count)
{
    struct function_inst_t *f_inst;
    struct function_inst_t *current_f_inst;
    u_int32_t i;

    /* Alloc memory fot function_inst_t structs */
    f_inst = kmalloc(sizeof(struct function_inst_t) * count, GFP_KERNEL);
    if (!f_inst)
        return NULL;

    /* Initialization */
    current_f_inst = f_inst;
    for (i = 0; i < count; i++) {
        current_f_inst->func_address = 0;
        current_f_inst->args_count = 0;
        current_f_inst->args = NULL;
        current_f_inst++;
    }

    return f_inst;
}





/* Destroy function_inst_t structs.
 * This function expects, that memory for structs array was allocated once for 
 * all elemenets. */
static void destroy_function_inst(struct function_inst_t **f_inst_pp,
                                  u_int32_t count)
{
    u_int32_t i;

    /* Loop over all function_inst_t structs */
    for (i = 0; i < count; i++) {
        /* Destroy args */
        kfree((*f_inst_pp)[i].args);
        (*f_inst_pp)[i].args = NULL;
    }

    /* Free function_inst_t memory */
    kfree(*f_inst_pp);
    *f_inst_pp = NULL;
}

/* Destroy library_inst_t structs.
 * This function expects, that memory for structs array was allocated once for 
 * all elemenets. */
static void destroy_library_inst(struct library_inst_t **l_inst_pp,
                                 u_int32_t count)
{
    u_int32_t i;

    /* Loop over all library_inst_t structs */
    for (i = 0; i < count; i++) {
        /* Destroy lib_path */
        kfree((*l_inst_pp)[i].lib_path);
        (*l_inst_pp)[i].lib_path = NULL;

        /* Destroy function_inst_t structs */
        destroy_function_inst(&((*l_inst_pp)[i].f_inst),
                              (*l_inst_pp)[i].func_count);
    }

    /* Free library_inst_t memory */
    kfree(*l_inst_pp);
    *l_inst_pp = NULL;
}

/* Destroy application_inst_t structs.
 * This function expects, that memory for structs array was allocated once for 
 * all elemenets. */
static void destroy_application_inst(struct application_inst_t **a_inst_pp,
                                     u_int32_t count)
{
    u_int32_t i;

    /* Loop over all application_inst_t structs */
    for (i = 0; i < count; i++) {
        /* Destroy app_path */
        kfree((*a_inst_pp)[i].app_path);
        (*a_inst_pp)[i].app_path = NULL;

        /* Destroy function_inst_t structs */
        destroy_function_inst(&((*a_inst_pp)[i].f_inst),
                              (*a_inst_pp)[i].func_count);

        /* Destroy library_inst_t structs */
        destroy_library_inst(&((*a_inst_pp)[i].l_inst),
                             (*a_inst_pp)[i].lib_count);
    }

    /* Free application_inst_t memory */
    kfree(*a_inst_pp);
    *a_inst_pp = NULL;
}

/* Destroy application_information_t structs.
 * This function expects, that memory for structs array was allocated once for 
 * all elemenets. */
void destroy_app_info(struct application_information_t **a_info_pp,
                      u_int32_t count)
{
    u_int32_t i;

    /* Loop over all application_information_t structs */
    for (i = 0; i < count; i++) {
        /* Destroy target application id */
        kfree((*a_info_pp)[i].t_app_id);
        (*a_info_pp)[i].t_app_id = NULL;

        /* Destroy exec path */
        kfree((*a_info_pp)[i].exec_path);
        (*a_info_pp)[i].exec_path = NULL;
    }

    /* Free all memory */
    kfree(*a_info_pp);
    *a_info_pp = NULL;
}

/* Destroy configuration_t structs.
 * This function expects, that memory for structs array was allocated once for 
 * all elemenets. */
void destroy_configuration(struct configuration_t **c_pp, u_int32_t count)
{
    /* There is no data to be destroyed, so, just free array mem */
    kfree(*c_pp);
    *c_pp = NULL;
}

/* Destroy user_space_inst_t structs.
 * This function expects, that memory for structs array was allocated once for 
 * all elemenets. */
void destroy_user_space_inst(struct user_space_inst_t **u_s_i_pp,
                                    u_int32_t count)
{
    u_int32_t i;

    /* Loop over all user_space_inst_t structs */
    for (i = 0; i < count; i++)
        /* Destroy application_inst_t structs */
        destroy_application_inst(&((*u_s_i_pp)[i].a_inst),
                                 (*u_s_i_pp)[i].app_count);

    /* Free user_space_inst_t memory */
    kfree(*u_s_i_pp);
    *u_s_i_pp = NULL;
}





/* Parse 4 bytes number */
static inline char *parse_int32(char *data, u_int32_t *dest)
{
    print_debug("%s = %d\n", __func__, *(u_int32_t *)data);

    memcpy(dest, data, sizeof(u_int32_t));

    return data + sizeof(u_int32_t);
}

/* Parse string */
static inline char *parse_string(char *data, char **dest)
{
    size_t string_len;

    print_debug("%s = %s\n", __func__, data);
    string_len = strlen(data) + 1;

    *dest = kmalloc(string_len, GFP_KERNEL);
    if (!(*dest))
        return NULL;

    /* We've added null-terminated symbol to string_len, so we expect that now
     * string from data would never exceeds string_len */
    strncpy(*dest, data, string_len);

    return data + string_len;
}

/* Parse char */
static inline char *parse_char(char *data, char *dest)
{
    print_debug("%s = %s\n", __func__, data);

    memcpy(dest, data, sizeof(char));

    return data + sizeof(char);
}


/* Parse 8 bytes number */
static inline char *parse_int64(char *data, u_int64_t *dest)
{
    print_debug("%s = %d\n", __func__, *(u_int64_t *)data);

    memcpy(dest, data, sizeof(u_int64_t));

    return data + sizeof(u_int64_t);
}

/* Parse application_information structure */
static char *parse_app_info(char *data, struct application_information_t *a_info)
{
    char *p = data;

    /* Target application type */
    p = parse_int32(p, &a_info->t_app_type);

    /* Target application ID */
    p = parse_string(p, &a_info->t_app_id);
    if (!p)
        return NULL;

    /* Executable path */
    p = parse_string(p, &a_info->exec_path);
    if (!p)
        return NULL;

    return p;
}

/* Parse configuration structure */
static char *parse_configuration(char *data, struct configuration_t *c)
{
    char *p = data;

    /* Use features flags */
    p = parse_int64(p, &c->use_features);

    /* System trace period */
    p = parse_int32(p, &c->sys_trace_period);

    /* Data message period */
    p = parse_int32(p, &c->data_msg_period);

    return p;
}

/* Parse function_inst_t structure */
static char *parse_function_inst(char *data, struct function_inst_t *f_inst)
{
    char *p = data;
    u_int32_t i;
    char *current_char;

    /* Function address */
    p = parse_int64(p, &f_inst->func_address);

    /* Args count */
    p = parse_int32(p, &f_inst->args_count);

    /* Allocate memory for args and parse them */
    f_inst->args = kmalloc(f_inst->args_count * sizeof(*(f_inst->args)),
                           GFP_KERNEL);
    if (!f_inst->args)
        return NULL;

    /* Initialize current char pointer */
    current_char = f_inst->args;

    for (i = 0; i < f_inst->args_count; i++) {
        p = parse_char(p, current_char);
        current_char++;
    }

    return p;
}

/* Parse library_inst_t structure */
static char *parse_library_inst(char *data, struct library_inst_t *l_inst)
{
    char *p = data;
    u_int32_t i;
    struct function_inst_t *current_f_inst;

    /* Library path */
    p = parse_string(p, &l_inst->lib_path);
    if (!p)
        goto lib_inst_path_alloc_fail;

    /* Funcs count */
    p = parse_int32(p, &l_inst->func_count);

    /* Allocation memory and parsing array of function_inst_t structures */
    l_inst->f_inst = create_function_inst(l_inst->func_count);
    if (!l_inst->f_inst)
        goto lib_inst_func_alloc_fail;

    current_f_inst = l_inst->f_inst;
    for (i = 0; i < l_inst->func_count; i++) {
        p = parse_function_inst(p, current_f_inst);
        if (!p)
            goto lib_inst_func_parse_fail;

        current_f_inst++;
    }

    return p;

/* Handle errors */
lib_inst_func_parse_fail:
    destroy_function_inst(&l_inst->f_inst, l_inst->func_count);

lib_inst_func_alloc_fail:
    kfree(l_inst->lib_path);

lib_inst_path_alloc_fail:
    return NULL;

}

/* Parse application_inst_t structure */
static char *parse_application_inst(char *data, 
                                    struct application_inst_t *a_inst)
{
    char *p = data;
    struct function_inst_t *current_f_inst;
    u_int32_t func_count;
    struct library_inst_t *current_l_inst;
    u_int32_t lib_count;
    u_int32_t i, j;

    /* Application path */
    p = parse_string(p, &a_inst->app_path);
    if (!p)
        goto app_inst_string_alloc_fail;

    /* Funcs count */
    p = parse_int32(p, &a_inst->func_count);

    /* Allocation memory and parsing array of function_inst_t structures */
    func_count = a_inst->func_count;
    a_inst->f_inst = create_function_inst(func_count);
    if (!a_inst->f_inst)
        goto app_inst_func_alloc_fail;

    /* Initialize pointer to the current function_inst_t struct */
    current_f_inst = a_inst->f_inst;

    /* Loop over all function_inst_t structures */
    for (i = 0; i < func_count; i++) {
        p = parse_function_inst(p, current_f_inst);
        if (!p)
            goto app_inst_func_parse_fail;
        current_f_inst++;
    }

    /* Libs count */
    p = parse_int32(p, &a_inst->lib_count);

    /* Allocation memory and parsing array of library_inst_t structures */
    lib_count = a_inst->lib_count;
    a_inst->l_inst = create_library_inst(lib_count);
    if (!a_inst->l_inst)
        goto app_inst_lib_alloc_fail;

    /* Initialize pointer to the current library_inst_t struct */
    current_l_inst = a_inst->l_inst;

    /* Loop over all library_inst_t structures */
    for (i = 0; i < lib_count; i++) {
        p = parse_library_inst(p, current_l_inst);
        if (!p)
            goto app_inst_lib_parse_fail;
        current_l_inst++;
    }

    return p;

/* Handle errors */
app_inst_lib_parse_fail:
    destroy_library_inst(a_inst->l_inst, a_inst->lib_count);

app_inst_func_parse_fail:
app_inst_lib_alloc_fail:
    destroy_function_inst(a_inst->f_inst, a_inst->func_count);

app_inst_func_alloc_fail:
    kfree(a_inst->app_path);

app_inst_string_alloc_fail:
    return NULL;
}

/* Parse user_space_inst structure */
static char *parse_user_space_inst(char *data, struct user_space_inst_t *u_s_i)
{
    char *p = data;
    struct application_inst_t *current_a_inst;
    u_int32_t app_count;
    u_int32_t i;

    /* Applications count */
    p = parse_int32(p, &u_s_i->app_count);

    /* If app_count == 0 => there is no data in user_space_inst struct => exit */
    if (u_s_i->app_count == 0)
        goto user_space_inst_app_count_is_0;

    /* Allocation memory and parsing array of application_inst structures */
    app_count = u_s_i->app_count;
    u_s_i->a_inst = create_application_inst(app_count);
    if (!u_s_i->a_inst)
        goto user_space_inst_app_alloc_fail;

    /* Initialize pointer to the current application_inst structure */
    current_a_inst = u_s_i->a_inst;

    /* Loop over all application_inst structures */
    for (i = 0; i < app_count; i++) {
        p = parse_application_inst(p, current_a_inst);
        if (!p)
            goto user_space_inst_app_parse_fail;
        current_a_inst++;
    }

user_space_inst_app_count_is_0:
    return p;

/* Handle errors */
user_space_inst_app_parse_fail:
    destroy_application_inst(u_s_i->a_inst, u_s_i->app_count);

user_space_inst_app_alloc_fail:
    return NULL;
}






int message_start_parser(void *message_ptr,
                         struct application_information_t **a_info_pp,
                         struct configuration_t **c_pp,
                         struct user_space_inst_t **u_s_i_pp)
{
    char *p = (char *)message_ptr;
    int result;

    /* Create app_information */
    *a_info_pp = create_app_info(1);
    if (!(*a_info_pp)) {
        result = -E_SMP_STRUCT_ALLOC_ERROR;
        goto msg_start_app_info_alloc_fail;
    }

    /* Parse app_information */
    p = parse_app_info(p, *a_info_pp);
    if (!p) {
        result = -E_SMP_PARSE_ERROR;
        goto msg_start_app_info_parse_fail;
    }

    /* Create config */
    *c_pp = create_configuration(1);
    if (!(*c_pp)) {
        result = -E_SMP_STRUCT_ALLOC_ERROR;
        goto msg_start_config_alloc_fail;
    }

    /* Parse config */
    p = parse_configuration(p, *c_pp);
    if (!p) {
        result = -E_SMP_PARSE_ERROR;
        goto msg_start_config_parse_fail;
    }

    /* Create user_space_inst */
    *u_s_i_pp = create_user_space_inst(1);
    if (!(*u_s_i_pp)) {
        result = -E_SMP_STRUCT_ALLOC_ERROR;
        goto msg_start_user_space_alloc_fail;
    }

    /* Parse user_space_inst */
    p = parse_user_space_inst(p, *u_s_i_pp);
    if (!p) {
        result = -E_SMP_PARSE_ERROR;
        goto msg_start_user_space_parse_fail;
    }

    return E_SMP_SUCCESS;

/* Handle errors */
msg_start_user_space_parse_fail:
    destroy_user_space_inst(*u_s_i_pp, 1);

msg_start_user_space_alloc_fail:
msg_start_config_parse_fail:
    destroy_configuration(*c_pp, 1);

msg_start_config_alloc_fail:
msg_start_app_info_parse_fail:
    destroy_app_info(*a_info_pp, 1);

msg_start_app_info_alloc_fail:
    return result;

}

int message_config_parser(void *message_ptr, struct configuration_t **c_pp)
{
    char *p = (char *)message_ptr;
    int result;

    /* Create config */
    *c_pp = create_configuration(1);
    if (!(*c_pp)) {
        result = -E_SMP_STRUCT_ALLOC_ERROR;
        goto msg_config_alloc_fail;
    }

    /* Parse config */
    p = parse_configuration(p, *c_pp);
    if (!p) {
        result = -E_SMP_PARSE_ERROR;
        goto msg_config_parse_fail;
    }

    return E_SMP_SUCCESS;

/* Handle errors */
msg_config_parse_fail:
    destroy_configuration(*c_pp, 1);

msg_config_alloc_fail:
    return result;
}

int message_swap_inst_parser(void *message_ptr,
                             struct user_space_inst_t **u_s_i_pp)
{
    char *p = (char *)message_ptr;
    int result;

    /* Create user_space_inst */
    *u_s_i_pp = create_user_space_inst(1);
    if (!(*u_s_i_pp)) {
        result = -E_SMP_STRUCT_ALLOC_ERROR;
        goto msg_swap_inst_alloc_fail;
    }

    /* Parse user_space_inst */
    p = parse_user_space_inst(p, *u_s_i_pp);
    if (!p) {
        result = -E_SMP_PARSE_ERROR;
        goto msg_swap_inst_parse_fail;
    }

/* Handle errors */
msg_swap_inst_parse_fail:
    destroy_user_space_inst(*u_s_i_pp, 1);

msg_swap_inst_alloc_fail:
    return result;

}

/* Get message size */
char *get_message_size(void __user *size_ptr, size_t *size)
{
    char *p = (char *)size_ptr;

    p = parse_int32((char *)p, (char *)size);

    return p;
}
