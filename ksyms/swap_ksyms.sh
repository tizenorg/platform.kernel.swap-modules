#!/bin/sh

MODULE_NAME=swap_ksyms
SYS_MAP_PACH=/mnt/nfs/System.map

# Check for running module in /proc/modules
RUNNING=`sed "/${MODULE_NAME}/ ! d" /proc/modules`

if [ "${RUNNING}" = "" ]; then
    ./bin/insmod.sh ${MODULE_NAME}.ko sm_path=${SYS_MAP_PACH}
    if [ $? -ne 0 ]; then
        echo "Error: unable to load ${MODULE_NAME}!"
	    exit 1
    fi
else
	echo "module ${MODULE_NAME} is already running!"
	exit 1
fi
