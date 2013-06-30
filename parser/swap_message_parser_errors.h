/* SWAP Message Parser error codes enumeration */

enum _swap_message_parser_errors {
    E_SMP_SUCCESS = 0,              /* Success */
    E_SMP_PARSE_ERROR = 1,          /* Error parsing application_information */
    E_SMP_STRUCT_ALLOC_ERROR = 2,   /* Error allocating memory for 
                                       application_information_t, 
                                       configuration_t or user_space_inst_t 
                                       structure */
    E_SMP_MSG_SIZE = 3,             /* Wrong message size */
    E_SMP_MSG_ALLOC = 4,            /* No mem to copy message */
    E_SMP_MSG_COPY = 5,             /* Error copy message to kernel */
    E_SMP_UNKNOWN_MESSAGE = 6       /* Unknown message */
};
