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

buffer_dir=${modules_dir}/buffer
writer_dir=${modules_dir}/writer
driver_dir=${modules_dir}/driver
kprobe_dir=${modules_dir}/kprobe
kprobe_arch_dir=${kprobe_dir}/arch
ksyms_dir=${modules_dir}/ksyms
ks_manager_dir=${modules_dir}/ks_manager
uprobe_dir=${modules_dir}/uprobe
uprobe_arch_dir=${uprobe_dir}/arch
us_manager_dir=${modules_dir}/us_manager
ks_features_dir=${modules_dir}/ks_features
sampler_dir=${modules_dir}/sampler
parser_dir=${modules_dir}/parser
energy_dir=${modules_dir}/energy

install_dir="/opt/swap/sdk"

rm -f ${kprobe_arch_dir}/asm
ln -s asm-${link_name} ${kprobe_arch_dir}/asm
rm -f ${uprobe_arch_dir}/asm
ln -s asm-${link_name} ${uprobe_arch_dir}/asm

buffer_module_name=swap_buffer.ko
buffer_inc=${modules_inc}
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${buffer_dir} modules || exit 1

writer_module_name=swap_writer.ko
writer_inc=${modules_inc}
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${writer_dir} \
	extra_cflags="-Werror -I${modules_dir}" modules || exit 1

driver_module_name=swap_driver.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${driver_dir} \
	extra_cflags="-I${modules_dir}" modules || exit 1

kprobe_module_name=swap_kprobe.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${kprobe_dir} \
	extra_cflags="-Werror -I${modules_dir} -I${kprobe_dir} -I${kprobe_arch_dir} -I${ksyms_dir}" \
	modules || exit 1

ks_manager_module_name=swap_ks_manager.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${ks_manager_dir} \
	extra_cflags="-Werror -I${kprobe_dir} -I${kprobe_arch_dir}" \
	modules || exit 1

uprobe_module_name=swap_uprobe.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${uprobe_dir} \
	extra_cflags="-Werror -I${modules_dir} -I${kprobe_dir} -I${kprobe_arch_dir} -I${uprobe_dir} -I${uprobe_arch_dir}" \
	modules || exit 1

us_manager_module_name=swap_us_manager.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${us_manager_dir} \
	extra_cflags="-I${modules_dir} -I${us_manager_dir} -I${kprobe_dir} -I${kprobe_arch_dir} -I${uprobe_dir} -I${uprobe_arch_dir} -I${driver_dir} -I${ksyms_dir}" \
	modules || exit 1

ks_features_module_name=swap_ks_features.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${ks_features_dir} \
	extra_cflags="-I${modules_dir} -I${kprobe_dir} -I${kprobe_arch_dir} -I${ksyms_dir}" \
	modules || exit 1

sampler_module_name=swap_sampler.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${sampler_dir} \
	extra_cflags="-I${modules_dir}" modules || exit 1

parser_module_name=swap_message_parser.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${parser_dir} \
	extra_cflags="-I${modules_dir}" modules || exit 1

energy_module_name=swap_energy.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${energy_dir} \
	extra_cflags="-I${modules_dir} -I${kprobe_dir} -I${kprobe_arch_dir}" modules || exit 1

modules=\
"${buffer_dir}/${buffer_module_name} \
${writer_dir}/${writer_module_name} \
${driver_dir}/${driver_module_name} \
${kprobe_dir}/${kprobe_module_name} \
${ks_manager_dir}/${ks_manager_module_name} \
${uprobe_dir}/${uprobe_module_name} \
${us_manager_dir}/${us_manager_module_name} \
${ks_features_dir}/${ks_features_module_name} \
${sampler_dir}/${sampler_module_name} \
${parser_dir}/${parser_module_name} \
${energy_dir}/${energy_module_name}"

# for m in ${modules} ; do
# 	sdb -e push $m ${install_dir}
# done
