#!/bin/sh


# name of the file with module
MODULE_FILE=swap_driver

# device name
DEVICE=swap_drv
DEFAULT_MAJOR=249

# name of device visible in /proc/devices
DEVICE_NAME=${DEVICE}

# name of the device file for /dev/
DEVICE_FILE=${DEVICE}

KSYMS=kallsyms_lookup_name

# ADDRESS for "kallsyms_lookup_name" function taken from /proc/kallsyms
ADDRESS=0x`sed "/ kallsyms_lookup_name/ ! d" /proc/kallsyms | sed "s/ T kallsyms_lookup_name//"`

if [ "${ADDRESS}" = "0x" ]; then
    if [ "$1" = "" ]; then
	echo "Enter kallsyms_lookup_name as parameter:"
	echo "insmod.sh <kallsyms_lookup_name address>"
	exit
    else
	ADDRESS=$1
	echo "kallsyms_lookup_name address is ${ADDRESS}"
    fi
fi

MAJOR=`sed "/${DEVICE_NAME}/ ! d" /proc/devices | sed "s/ ${DEVICE_NAME}//"`
if [ "${MAJOR}" != "" ] ; then
    echo "SWAP Driver is already loaded!"
    exit 1
    rmmod ${MODULE_FILE}
    MAJOR=`sed "/${DEVICE_NAME}/ ! d" /proc/devices | sed "s/ ${DEVICE_NAME}//"`
    if [ "${MAJOR}" != "" ] ; then
        echo "Error: Unable to unload driver module '${MODULE_FILE}'"
        exit 1
    fi
fi

if [ ! -c /dev/${DEVICE_FILE} ] ; then
	echo "WARNING: Creating device node with major number [${DEFAULT_MAJOR}]!"
	mknod /dev/${DEVICE_FILE} c ${DEFAULT_MAJOR} 0
	if [ $? -ne 0 ]; then
	    echo "Error: Unable to create device node!"
	    exit
	fi
	chmod a+r /dev/${DEVICE_FILE}
fi

# load driver module
echo "loading module '${MODULE_FILE}'"
insmod ${MODULE_FILE}.ko fp_kallsyms_lookup_name=${ADDRESS} device_name=${DEVICE_NAME} device_major=${DEFAULT_MAJOR}
if [ $? -ne 0 ]; then
    echo "Error: Unable to load Swap Driver!"
fi
MAJOR=`sed "/${DEVICE_NAME}/ ! d" /proc/devices | sed "s/ ${DEVICE_NAME}//"`

