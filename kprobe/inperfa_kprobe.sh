#!/bin/sh

SWAP_KPROBE=inperfa_kprobe
KSYMS=kallsyms_lookup_name

# ADDRESS for "kallsyms_lookup_name" function taken from /proc/kallsyms
ADDRESS=0x`sed "/ kallsyms_lookup_name/ ! d" /proc/kallsyms | sed "s/ T kallsyms_lookup_name//"`

if [ "${ADDRESS}" = "0x" ]; then
    if [ "$1" = "" ]; then
	echo "Enter kallsyms_lookup_name as parameter:"
	echo "inperfa_kprobe.sh <kallsyms_lookup_name address>"
	exit 1
    else
	ADDRESS=$1
	echo "kallsyms_lookup_name address is ${ADDRESS}"
    fi
fi

# Check for running module in /proc/modules
RUNNING=`sed "/${SWAP_KPROBE}/ ! d" /proc/modules`

if [ "${RUNNING}" = "" ]; then
    insmod ${SWAP_KPROBE}.ko ksyms=${ADDRESS}
    if [ $? -ne 0 ]; then
         echo "Error: unable to load Inperfa KProbe!"
    fi
else
	echo "Inperfa Kprobe is already running!"
	exit 1
fi
