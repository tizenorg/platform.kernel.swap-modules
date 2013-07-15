#!/bin/sh

MODULE_NAME=swap_driver_new

# Check for running module in /proc/modules
RUNNING=`sed "/${MODULE_NAME}/ ! d" /proc/modules`

if [ "${RUNNING}" = "" ]; then
    ./bin/insmod.sh ${MODULE_NAME}.ko
    if [ $? -ne 0 ]; then
            echo "Error: unable to load ${MODULE_NAME} module!"
	    exit 1
    fi
else
	echo "${MODULE_NAME} module is already running!"
	exit 1
fi
