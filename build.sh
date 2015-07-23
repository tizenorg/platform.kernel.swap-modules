#!/bin/bash

modules_dir=`pwd`

if [ "$#" -lt 2 ] ; then
	echo "Usage: $0 <kernel dir> <arch (arm/i386)> [<cross compile>]"
	exit 1
fi

kernel_dir=$1
arch=$2
cross_compile=$3

if [ ${arch} = "arm" ] ; then
	link_name="arm"
elif [ ${arch} = "i386" ] ; then
	link_name="x86"
else
	echo "Unknown arch $arch"
	exit 1
fi

install_dir="/opt/swap/sdk"

asm_kprobe_dir=${modules_dir}/kprobe/arch/${link_name}/
asm_uprobe_dir=${modules_dir}/uprobe/arch/${link_name}/

make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} \
	M=${modules_dir} extra_cflags="-Werror -I${modules_dir} -I${asm_kprobe_dir} \
	-I${asm_uprobe_dir}" modules || exit 1

