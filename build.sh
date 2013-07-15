#!/bin/bash

modules_dir=`pwd`
# kernel_dir="/home/kain/dev/inperfa/kernel/redwood/linux-3.4-exynos"
kernel_dir="/home/alexander/vanilla_kernels/linux-3.8.6"
cross_compile=/home/alexander/dev/u1_slp/arm-linux-gnueabi-gcc4.4.1-glibc2.11.1/bin/arm-none-linux-gnueabi-
arch=arm
#arch=i386

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
driver_new_dir=${modules_dir}/driver_new
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

driver_dir=${modules_dir}/driver
common_dir=${modules_dir}/../common

install_dir="/opt/swap/sdk"

rm ${kprobe_arch_dir}/asm
ln -s asm-${link_name} ${kprobe_arch_dir}/asm
rm ${uprobe_arch_dir}/asm
ln -s asm-${link_name} ${uprobe_arch_dir}/asm

buffer_module_name=swap_buffer.ko
buffer_inc=${modules_inc}
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${buffer_dir} modules || exit 1

writer_module_name=swap_writer.ko
writer_inc=${modules_inc}
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${writer_dir} modules || exit 1

driver_new_module_name=swap_driver_new.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${driver_new_dir} \
	extra_cflags="-I${modules_dir}" modules || exit 1

kprobe_module_name=swap_kprobe.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${kprobe_dir} \
	extra_cflags="-I${modules_dir} -I${kprobe_dir} -I${kprobe_arch_dir} -I${ksyms_dir}" \
	modules || exit 1

ks_manager_module_name=swap_ks_manager.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${ks_manager_dir} \
	extra_cflags="-I${kprobe_dir} -I${kprobe_arch_dir}" \
	modules || exit 1

uprobe_module_name=swap_uprobe.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${uprobe_dir} \
	extra_cflags="-I${modules_dir} -I${kprobe_dir} -I${kprobe_arch_dir} -I${uprobe_dir} -I${uprobe_arch_dir}" \
	modules || exit 1

us_manager_module_name=swap_us_manager.ko
make CROSS_COMPILE=${cross_compile} ARCH=${arch} -C ${kernel_dir} M=${us_manager_dir} \
	extra_cflags="-I${modules_dir} -I${us_manager_dir} -I${kprobe_dir} -I${kprobe_arch_dir} -I${uprobe_dir} -I${uprobe_arch_dir} -I${driver_dir} -I${common_dir} -I${ksyms_dir}" \
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

modules=\
"${buffer_dir}/${buffer_module_name} \
${writer_dir}/${writer_module_name} \
${driver_new_dir}/${driver_new_module_name} \
${kprobe_dir}/${kprobe_module_name} \
${ks_manager_dir}/${ks_manager_module_name} \
${uprobe_dir}/${uprobe_module_name} \
${us_manager_dir}/${us_manager_module_name} \
${ks_features_dir}/${ks_features_module_name} \
${sampler_dir}/${sampler_module_name} \
${parser_dir}/${parser_module_name}"

for m in ${modules} ; do
	sdb -e push $m ${install_dir}
done
