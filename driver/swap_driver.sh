#!/bin/sh


# name of the file with module
MODULE_FILE=swap_driver

# device name
DEVICE=__DEV_NAME__
DEVICE_MAJOR=__DEV_MAJOR__

# name of device visible in /proc/devices
DEVICE_NAME=${DEVICE}

# name of the device
DEVICE_FILE=__DEV_DIR__/${DEVICE}

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

if [ ! -c ${DEVICE_FILE} ] ; then
	echo "WARNING: Creating device node with major number [${DEVICE_MAJOR}]!"
	mknod ${DEVICE_FILE} c ${DEVICE_MAJOR} 0
	if [ $? -ne 0 ]; then
	    echo "Error: Unable to create device node!"
	    exit 1
	fi
	chmod a+r ${DEVICE_FILE}
else
	# stat is better, but DTV doesn't have stat
	DEVICE_MAJOR=`ls -l ${DEVICE_FILE} | awk '{sub(/,/,"",$5); print $5}'`
fi

# load driver module
echo "loading module '${MODULE_FILE}'"
./bin/insmod.sh ${MODULE_FILE}.ko device_name=${DEVICE_NAME} device_major=${DEVICE_MAJOR}
if [ $? -ne 0 ]; then
    echo "Error: Unable to load Swap Driver!"
    exit 1
fi
MAJOR=`sed "/${DEVICE_NAME}/ ! d" /proc/devices | sed "s/ ${DEVICE_NAME}//"`

