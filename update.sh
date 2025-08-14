#!/bin/bash

sudo modprobe nbd max_part=8
sudo qemu-nbd -c /dev/nbd0 /mnt/c/Users/adity/other/other_2.vdi
sudo fdisk -l /dev/nbd0
sudo mount -o loop /dev/nbd0 /mnt/c/Users/adity/Desktop/VOSTROX/disk/
sync
sudo cp -r /mnt/c/Users/adity/Desktop/VOSTROX/build/temp/os/* /mnt/c/Users/adity/Desktop/VOSTROX/disk/
sudo umount /mnt/c/Users/adity/Desktop/VOSTROX/disk/
sudo qemu-nbd -d /dev/nbd0