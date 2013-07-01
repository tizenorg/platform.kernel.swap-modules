/* SWAP driver message handler */

#include <linux/slab.h>
#include <asm/uaccess.h>

#include "swap_message_parser_errors.h"
#include "parser_defs.h"
#include "message_handler.h"
#include "message_parser.h"
#include "protocol_description.h"

int message_start(void __user *message_ptr)
{
    int result;
    size_t msg_size;
    void *msg_in_kern;
    struct application_information_t *a_info;
    struct configuration_t *c;
    struct user_space_inst_t *u_s_i;

    /* Get message size and skip size of msg size variable */
    message_ptr = get_message_size(message_ptr, &msg_size);
    if (msg_size == 0) {
        result = -E_SMP_MSG_SIZE;
        goto msg_start_wrong_size;
    }

    /* Alloc memory for message in kernel space */
    msg_in_kern = kmalloc(msg_size, GFP_KERNEL);
    if (!msg_in_kern) {
        result = -E_SMP_MSG_ALLOC;
        goto msg_start_kmalloc_fail;
    }

    /* Copy message to kernel space */
    if (copy_from_user(msg_in_kern, message_ptr, msg_size)) {
        result = -E_SMP_MSG_COPY;
        goto msg_start_error_copy;
    }

    /* Parse message */
    result = message_start_parser(msg_in_kern, &a_info, &c, &u_s_i);
    if (result != E_SMP_SUCCESS) {
        goto msg_start_parse_fail;
    }


    // TODO Use Salva



    /* Destroy application_information_t struct */
    destroy_app_info(&a_info, 1);

    /* Destroy configuration_t struct */
    destroy_configuration(&c, 1);

    /* Destroy user_space_inst_t struct */
    destroy_user_space_inst(&u_s_i, 1);

    return E_SMP_SUCCESS;

/* Handle errors */
msg_start_parse_fail:
msg_start_error_copy:
    kfree(msg_in_kern);

msg_start_kmalloc_fail:
msg_start_wrong_size:
    return result;
}

int message_stop(void)
{
    int result;

// TODO Use Slava
}

int message_config(void __user *message_ptr)
{
    int result;
    size_t msg_size;
    void *msg_in_kern;
    struct configuration_t *c;

    /* Get message size and skip size of msg size variable */
    message_ptr = get_message_size(message_ptr, &msg_size);
    if (msg_size == 0) {
        result = -E_SMP_MSG_SIZE;
        goto msg_config_wrong_size;
    }

    /* Alloc memory for message in kernel space */
    msg_in_kern = kmalloc(msg_size, GFP_KERNEL);
    if (!msg_in_kern) {
        result = -E_SMP_MSG_ALLOC;
        goto msg_config_kmalloc_fail;
    }

    /* Copy message to kernel space */
    if (copy_from_user(msg_in_kern, message_ptr, msg_size)) {
        result = -E_SMP_MSG_COPY;
        goto msg_config_error_copy;
    }

    /* Parse message */
    result = message_config_parser(msg_in_kern, &c);
    if (result != E_SMP_SUCCESS) {
        goto msg_config_parse_fail;
    }


    // TODO Use Salva



    /* Destroy configuration_t struct */
    destroy_configuration(&c, 1);

    return E_SMP_SUCCESS;

/* Handle errors */
msg_config_parse_fail:
msg_config_error_copy:
    kfree(msg_in_kern);

msg_config_kmalloc_fail:
msg_config_wrong_size:
    return result;
}

int message_swap_inst_add(void __user *message_ptr)
{
    int result;
    size_t msg_size;
    void *msg_in_kern;
    struct user_space_inst_t *u_s_i;

    /* Get message size and skip size of msg size variable */
    message_ptr = get_message_size(message_ptr, &msg_size);
    if (msg_size == 0) {
        result = -E_SMP_MSG_SIZE;
        goto msg_swap_inst_add_wrong_size;
    }

    /* Alloc memory for message in kernel space */
    msg_in_kern = kmalloc(msg_size, GFP_KERNEL);
    if (!msg_in_kern) {
        result = -E_SMP_MSG_ALLOC;
        goto msg_swap_inst_add_kmalloc_fail;
    }

    /* Copy message to kernel space */
    if (copy_from_user(msg_in_kern, message_ptr, msg_size)) {
        result = -E_SMP_MSG_COPY;
        goto msg_swap_inst_add_error_copy;
    }

    /* Parse message */
    result = message_swap_inst_parser(msg_in_kern, &u_s_i);
    if (result != E_SMP_SUCCESS) {
        goto msg_swap_inst_add_parse_fail;
    }


    // TODO Use Salva



    /* Destroy user_space_inst_t struct */
    destroy_user_space_inst(&u_s_i, 1);

    return E_SMP_SUCCESS;

/* Handle errors */
msg_swap_inst_add_parse_fail:
msg_swap_inst_add_error_copy:
    kfree(msg_in_kern);

msg_swap_inst_add_kmalloc_fail:
msg_swap_inst_add_wrong_size:
    return result;
}

int message_swap_inst_remove(void __user *message_ptr)
{
    int result;
    size_t msg_size;
    void *msg_in_kern;
    struct user_space_inst_t *u_s_i;

    /* Get message size and skip size of msg size variable */
    message_ptr = get_message_size(message_ptr, &msg_size);
    if (msg_size == 0) {
        result = -E_SMP_MSG_SIZE;
        goto msg_swap_inst_rem_wrong_size;
    }

    /* Alloc memory for message in kernel space */
    msg_in_kern = kmalloc(msg_size, GFP_KERNEL);
    if (!msg_in_kern) {
        result = -E_SMP_MSG_ALLOC;
        goto msg_swap_inst_rem_kmalloc_fail;
    }

    /* Copy message to kernel space */
    if (copy_from_user(msg_in_kern, message_ptr, msg_size)) {
        result = -E_SMP_MSG_COPY;
        goto msg_swap_inst_rem_error_copy;
    }

    /* Parse message */
    result = message_swap_inst_parser(msg_in_kern, &u_s_i);
    if (result != E_SMP_SUCCESS) {
        goto msg_swap_inst_rem_parse_fail;
    }


    // TODO Use Salva



    /* Destroy user_space_inst_t struct */
    destroy_user_space_inst(&u_s_i, 1);

    return E_SMP_SUCCESS;

/* Handle errors */
msg_swap_inst_rem_parse_fail:
msg_swap_inst_rem_error_copy:
    kfree(msg_in_kern);

msg_swap_inst_rem_kmalloc_fail:
msg_swap_inst_rem_wrong_size:
    return result;
}
