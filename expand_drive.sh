#!/bin/bash
# This script will expand the Publisher partition to use all available space AFTER the physical hard drive 
# space has been increased on the Virtual Machine HyperVisor
# It will then install linux-image-generic to allow for Kernel updates
sudo growpart /dev/sda 3
sudo pvresize /dev/sda3
sudo lvresize -l+100%FREE --resizefs /dev/mapper/ubuntu--vg-ubuntu--lv
sudo apt update
sudo apt install linux-
sudo apt upgrade -y
