#!/bin/bash
# This script will expand the Publisher partition to use all available space AFTER the physical hard drive 
# space has been increased on the Virtual Machine HyperVisor
# It will then install linux-image-generic to allow for Kernel updates
# The below 3 commands will grow the partition AFTER the physical hard drive has been increased
sudo growpart /dev/sda 3
sudo pvresize /dev/sda3
sudo lvresize -l+100%FREE --resizefs /dev/mapper/ubuntu--vg-ubuntu--lv
# The below will install linux-image-generic apt package that will manage kernel updates as part of apt upgrade 
sudo apt update
sudo apt install linux-image-generic -y
sudo apt upgrade -y
sudo reboot
