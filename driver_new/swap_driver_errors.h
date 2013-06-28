/* SWAP Driver error codes enumeration */

enum _swap_driver_errors {
    E_SD_SUCCESS = 0,               /* Success */
    E_SD_ALLOC_CHRDEV_FAIL = 1,     /* alloc_chrdev_region failed */
    E_SD_CDEV_ALLOC_FAIL = 2,       /* cdev_alloc failed */
    E_SD_CDEV_ADD_FAIL = 3,         /* cdev_add failed */
    E_SD_CLASS_CREATE_FAIL = 4,     /* class_create failed */
    E_SD_DEVICE_CREATE_FAIL = 5,    /* device_create failed */
    E_SD_NO_SPLICE_FUNCS = 6,       /* splice_* funcs not found */
    E_SD_NO_DATA_TO_READ = 7,       /* swap_buffer_get tells us that there is no
                                       readable subbuffers */
    E_SD_NO_BUSY_SUBBUFFER = 8,     /* No busy subbuffer */
    E_SD_WRONG_SUBBUFFER_PTR = 9,    /* Wrong subbuffer pointer passed to
                                       swap_buffer module */
    E_SD_BUFFER_ERROR = 10,         /* Unhandled swap_buffer error */
    E_SD_WRITE_ERROR = 11,          /* Write to subbuffer error */
    E_SD_WRONG_ARGS = 12,           /* Arguments, passed to the func, doesn't 
                                       pass sanity check */
    E_SD_NO_MEMORY = 13,            /* No memory to allocate */
    E_SD_UNINIT_ERROR = 14          /* swap_buffer uninitialization error */
};
