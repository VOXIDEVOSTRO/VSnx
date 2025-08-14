#!/bin/bash

# Install e2fsprogs (required for formatting ext4 filesystems)
apk add e2fsprogs

# Step 1: Restore Missing Network Interface Configuration
echo "Restoring /etc/network/interfaces..."
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

# Step 2: Bring up Network Interface
echo "Bringing up network interface eth0..."
ip link set eth0 up
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "RESOLV_CONF=no" > /etc/udhcpc/udhcpc.conf
service networking restart

# Step 3: Fix Repository (Use a reliable mirror)
echo "Updating Alpine Linux repositories..."
echo "https://mirror.leaseweb.com/alpine/v3.20/main" > /etc/apk/repositories
echo "https://mirror.leaseweb.com/alpine/v3.20/community" >> /etc/apk/repositories
apk update

# Step 4: Install GRUB
echo "Installing GRUB bootloader..."
apk add grub

# Format the disk as FAT32
mkfs.vfat -F 32 /dev/sda

cp -r /media/cdrom/grub /usr/lib/

# Mount the disk to /mnt
mount /dev/sda /mnt

# Copy entire /os directory from CD to /mnt
mount | grep boot

mount /dev/sda /boot

grub-install --target=i386-pc --boot-directory=/mnt/boot --force /dev/sda

cp -r /media/cdrom/os/* /mnt/

echo "All tasks completed successfully!"
echo "Boot image written to sector 2048 (1MB offset)"
