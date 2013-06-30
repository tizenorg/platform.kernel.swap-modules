/* Message parser interface. */

#ifndef __MESSAGE_PARSER_H__
#define __MESSAGE_PARSER_H__

#include "protocol_description.h"

int message_start_parser(void *message_ptr,
                         struct application_information_t **a_info_pp,
                         struct configuration_t **c_pp,
                         struct user_space_inst_t **u_s_i_pp);
int message_config_parser(void *message_ptr, struct configuration_t **c_pp);
int message_swap_inst_parser(void *message_ptr,
                             struct user_space_inst_t **u_s_i_pp);

void destroy_app_info(struct application_information_t **a_info_pp,
                      u_int32_t count);
void destroy_configuration(struct configuration_t **c_pp, u_int32_t count);
void destroy_user_space_inst(struct user_space_inst_t **u_s_i_pp,
                             u_int32_t count);

char *get_message_size(void __user *size_ptr, size_t *size);

#endif /* __MESSAGE_PARSER_H__ */
