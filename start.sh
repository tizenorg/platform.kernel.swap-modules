#!/bin/sh

insmod swap_buffer.ko || exit 1  # buffer is loaded
insmod swap_ksyms.ko || exit 1
insmod swap_driver.ko || exit 1  # driver is loaded
insmod swap_writer.ko || exit 1
insmod swap_kprobe.ko || exit 1  # kprobe is loaded
insmod swap_ks_manager.ko || exit 1  # ks_manager is loaded
insmod swap_uprobe.ko || exit 1  # uprobe is loaded
insmod swap_us_manager.ko || exit 1  # us_manager is loaded
insmod swap_ks_features.ko || exit 1  # ks_features is loaded
insmod swap_sampler.ko || exit 1
insmod swap_energy.ko || exit 1
insmod swap_message_parser.ko || exit 1  # parser is loaded


# Energy coefficients
# CPU coefficients are divided by 10^6 because
#  - they were calculated for mAs
#  - SWAP modules count nanoseconds
#  - result should be exposed in uAs
# Flash coefficients are multiplied by 10^3 because
#  - they were calculated for mAs
#  - result should be exposed in uAs
# LCD coefficients are divided by 10^6 because
#  - they were calculated for mAs
#  - result should be exposed in uAs

# cpu idle: 76.8301 / 1
echo 76830 > /sys/kernel/debug/swap/energy/cpu_idle/numerator &&
echo 1000000000 > /sys/kernel/debug/swap/energy/cpu_idle/denominator &&

# cpu running: 253.29 / 1
echo 253290 > /sys/kernel/debug/swap/energy/cpu_running/numerator &&
echo 1000000000 > /sys/kernel/debug/swap/energy/cpu_running/denominator &&

# flash read:  106.249 / 69998585
echo 106249 > /sys/kernel/debug/swap/energy/flash_read/numerator &&
echo 69998585 > /sys/kernel/debug/swap/energy/flash_read/denominator &&

# flash write: 131.443 / 31129333
echo 131443 > /sys/kernel/debug/swap/energy/flash_write/numerator &&
echo 31129333 > /sys/kernel/debug/swap/energy/flash_write/denominator &&

# LCD:
if [ -d /sys/kernel/debug/swap/energy/lcd/ ]
then
	# lcd max (white max - black max) / 2: 255 / 1
	echo 255 > `ls /sys/kernel/debug/swap/energy/lcd/*/max_num` &&
	echo 1000000 > `ls /sys/kernel/debug/swap/energy/lcd/*/max_denom` &&

	# lcd min (white min - black min) / 2: 179 / 1
	echo 179 > `ls /sys/kernel/debug/swap/energy/lcd/*/min_num` &&
	echo 1000000 > `ls /sys/kernel/debug/swap/energy/lcd/*/min_denom`
fi
