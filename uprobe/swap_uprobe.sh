#!/bin/sh

SWAP_UPROBE=swap_uprobe

# Check for running module in /proc/modules
RUNNING=`sed "/${SWAP_UPROBE}/ ! d" /proc/modules`

if [ "${RUNNING}" = "" ]; then
    ./bin/insmod.sh ${SWAP_UPROBE}.ko
    if [ $? -ne 0 ]; then
            echo "Error: unable to load SWAP UProbe!"
	    exit 1
    fi
else
	echo "SWAP Uprobe is already running!"
	exit 1
fi
