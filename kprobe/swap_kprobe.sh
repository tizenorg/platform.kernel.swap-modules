#!/bin/sh

SWAP_KPROBE=swap_kprobe

# Check for running module in /proc/modules
RUNNING=`sed "/${SWAP_KPROBE}/ ! d" /proc/modules`

if [ "${RUNNING}" = "" ]; then
    ./bin/insmod.sh ${SWAP_KPROBE}.ko
    if [ $? -ne 0 ]; then
            echo "Error: unable to load SWAP KProbe!"
	    exit 1
    fi
else
	echo "SWAP Kprobe is already running!"
	exit 1
fi
