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
driver_dir=${modules_dir}/driver
writer_dir=${modules_dir}/writer
kprobe_dir=${modules_dir}/kprobe
kprobe_arch_dir=${kprobe_dir}/arch
ksyms_dir=${modules_dir}/ksyms
ks_manager_dir=${modules_dir}/ks_manager
uprobe_dir=${modules_dir}/uprobe
uprobe_arch_dir=${uprobe_dir}/arch
us_manager_dir=${modules_dir}/us_manager
ks_features_dir=${modules_dir}/ks_features
sampler_dir=${modules_dir}/sampler
energy_dir=${modules_dir}/energy
parser_dir=${modules_dir}/parser
retprobe_dir=${modules_dir}/retprobe
webprobe_dir=${modules_dir}/webprobe
task_data_dir=${modules_dir}/task_data
preload_dir=${modules_dir}/preload
fbiprobe_dir=${modules_dir}/fbiprobe

buffer_module_name=swap_buffer.ko
driver_module_name=swap_driver.ko
writer_module_name=swap_writer.ko
kprobe_module_name=swap_kprobe.ko
ks_manager_module_name=swap_ks_manager.ko
uprobe_module_name=swap_uprobe.ko
us_manager_module_name=swap_us_manager.ko
ks_features_module_name=swap_ks_features.ko
sampler_module_name=swap_sampler.ko
energy_module_name=swap_energy.ko
parser_module_name=swap_message_parser.ko
ksyms_module_name=swap_ksyms.ko
retprobe_module_name=swap_retprobe.ko
webprobe_module_name=swap_webprobe.ko
task_data_module_name=swap_task_data.ko
preload_module_name=swap_preload.ko
fbiprobe_module_name=swap_fbiprobe.ko

install_dir="/opt/swap/sdk"

asm_kprobe_dir=${modules_dir}/kprobe/arch/${link_name}/
asm_uprobe_dir=${modules_dir}/uprobe/arch/${link_name}/

make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} \
	M=${modules_dir} extra_cflags="-Werror -I${modules_dir} -I${asm_kprobe_dir} \
	-I${asm_uprobe_dir}" modules || exit 1

modules=\
"${buffer_dir}/${buffer_module_name} \
${driver_dir}/${driver_module_name} \
${writer_dir}/${writer_module_name} \
${kprobe_dir}/${kprobe_module_name} \
${ks_manager_dir}/${ks_manager_module_name} \
${uprobe_dir}/${uprobe_module_name} \
${us_manager_dir}/${us_manager_module_name} \
${ks_features_dir}/${ks_features_module_name} \
${sampler_dir}/${sampler_module_name} \
${energy_dir}/${energy_module_name} \
${parser_dir}/${parser_module_name} \
${ksyms_dir}/${ksyms_module_name} \
${retprobe_dir}/${retprobe_module_name} \
${webprobe_dir}/${webprobe_module_name} \
${task_data_dir}/${task_data_module_name} \
${preload_dir}/${preload_module_name} \
${fbiprobe_dir}/${fbiprobe_module_name}"

for m in ${modules} ; do
	${cross_compile}strip -x -g $m
#	sdb -e push $m ${install_dir}
done
