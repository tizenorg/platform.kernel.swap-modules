#!/bin/sh

insmod swap_buffer.ko || exit 1  # buffer is loaded
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
