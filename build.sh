#!/usr/bin/env bash
# NOTE: This requires GNU getopt.  On Mac OS X and FreeBSD, you have to install
# this separately; see below.

IDENT=${0}

show_usage_and_exit () {
	echo -e "Usage: ${IDENT} <options> <compile|check|clean>"
	echo -e "\tOptions:"
	echo -e "\t--verbose"
	echo -e "\t--file <config file>"
#	echo -e "\t--debug"
	echo -e "\t--kernel <kernel path>"
	echo -e "\t--arch <arm|i386>"
	echo -e "\t[--toolchain <cross compile path>]"
	exit 1
}

TEMP=`getopt -o vk:t:a:f: --long verbose,kernel:,toolchain:,arch:,file: \
	-n '${IDENT}' -- "$@"`

if [ $? != 0 ] ; then
	show_usage_and_exit
fi

# Note the quotes around `$TEMP': they are essential!
eval set -- "$TEMP"

MDIR=`pwd`
VERBOSE=false
CONFIG_FILE="build.config"
KERNELDIR=""
TOOLCHAIN=""
ARCH=""

while true; do
	case "$1" in
		-v | --verbose ) VERBOSE=true; shift ;;
		-k | --kernel ) KERNELDIR="$2"; shift 2 ;;
		-t | --toolchain ) TOOLCHAIN="$2"; shift 2;;
		-a | --arch ) ARCH="$2"; shift 2;;
		-f | --file ) CONFIG_FILE="$2"; shift 2;;
		-- ) shift; break ;;
		* ) break ;;
	esac
done

if  [ "${1}" != "compile" -a "${1}" != "clean" -a "${1}" != "check"  ] ; then
	ACTION="compile"
        ARCH=${2}
	KERNELDIR=${1}
	if [ "${3}" != "" ] ; then
		TOOLCHAIN=${3}
	fi
else
	if [ -r ${CONFIG_FILE} ]; then
		. ${CONFIG_FILE}
		KERNELDIR=${kernel}
		TOOLCHAIN=${toolchain}
		ARCH=$arch
	fi
	ACTION="${1}"
fi

if [ "${KERNELDIR}" = "" ] ; then
	show_usage_and_exit
fi

if [ "${ARCH}" = "arm" ] ; then
	LINKNAME="arm"
elif [ "${ARCH}" = "i386" ] ; then
	LINKNAME="x86"
else
	show_usage_and_exit
fi

MCFLAGS="-Werror"

CMDLINE_ARGS=""
CMDLINE_ARGS="CROSS_COMPILE=${TOOLCHAIN} ARCH=${ARCH} -C ${KERNELDIR}"
CMDLINE_ARGS="${CMDLINE_ARGS} M=${MDIR} MCFLAGS=${MCFLAGS} LINKNAME=${LINKNAME}"

if [ "${ACTION}" = "check" ] ; then
	CMDLINE="make C=2 CF=\"-Wsparse-all\" ${CMDLINE_ARGS} modules"
elif [ "${ACTION}" = "clean" ] ; then
	CMDLINE="make ${CMDLINE_ARGS} clean"
else
	CMDLINE="make ${CMDLINE_ARGS} modules"
fi

if [ ${VERBOSE} = "true" ] ; then
	CMDLINE="${CMDLINE} V=1"
fi

#echo -n "CMDLINE ${CMDLINE}\n"

${CMDLINE} || exit 1

exit 0

