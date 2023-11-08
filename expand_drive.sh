#!/bin/bash

# This script will expand the Publisher partition to use all available space AFTER the physical hard drive 
# space has been increased on the Virtual Machine HyperVisor
# It will then install linux-image-generic to allow for Kernel updates
# The below 3 commands will grow the partition AFTER the physical hard drive has been increased

# Check if the script is run as root
if [ "$(id -u)" != 0 ]; then
  echo "Please run this script as root or using sudo."
  exit 1
fi

# Check if required commands are available
command -v growpart >/dev/null 2>&1 || { echo "growpart is not installed. Aborting." >&2; exit 1; }
command -v pvresize >/dev/null 2>&1 || { echo "pvresize is not installed. Aborting." >&2; exit 1; }
command -v lvresize >/dev/null 2>&1 || { echo "lvresize is not installed. Aborting." >&2; exit 1; }

# Grow the partition AFTER the physical hard drive has been increased
sudo growpart /dev/sda 3 && sudo pvresize /dev/sda3 && sudo lvresize -l+100%FREE --resizefs /dev/mapper/ubuntu--vg-ubuntu--lv

#Check partition has been increased and disk space is above 6GB
reqSpace=6000000
availSpace=$(df "$HOME" | awk 'NR==2 { print $4 }')
if (( availSpace < reqSpace )); then
  echo "Not enough space" >&2
  exit 1
fi

#ensure all options are answered with yes to make it completely uninteractive
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef -y upgrade

# The below will install linux-image-generic apt package that will manage kernel updates as part of apt upgrade 
sudo apt update && sudo apt install linux-image-generic -y && sudo apt upgrade -y && sudo reboot
