#!/bin/bash

# Copyright (c) Shubham Mishra. All rights reserved.
# Licensed under the MIT License.

# Runs as root.
# Change the default username from ubuntu to psladmin
usermod -l psladmin ubuntu
usermod -m -d /home/psladmin psladmin

# Add the psladmin user to the sudoers file
echo "psladmin ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers


# Docker keys and repos
apt-get update
apt-get install ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update

# Install Docker
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Non-root run
usermod -aG docker psladmin

# Restart on reboot
systemctl enable docker.service
systemctl enable containerd.service

# PSL dependencies
apt-get install -y screen
apt-get install -y build-essential cmake clang llvm pkg-config
apt-get install -y jq
apt-get install -y protobuf-compiler
apt-get install -y linux-tools-common linux-tools-generic linux-tools-`uname -r`
apt-get install -y net-tools
apt-get install -y ca-certificates curl libssl-dev
apt-get install -y librocksdb-dev libprotobuf-dev
apt-get install -y python3-pip python3-virtualenv


# Increase open file limits

echo "*	soft	nofile	50000" >> /etc/security/limits.conf
echo "*	hard	nofile	50000" >> /etc/security/limits.conf


# Mount the EBS SSD.
# AWS + Ubuntu 24.04 => The name for disk is /dev/nvme1n1
# It may not be present (for sevpool and clientpool)

if [ -b /dev/nvme1n1 ]; then
    mkfs.ext4 /dev/nvme1n1
    mkdir /data
    mount /dev/nvme1n1 /data
    chmod -R 777 /data
fi


# Turns out AWS lets you login to the instance before this script ends executing.
# We will have a flag file to check for finishing.

echo "VM Ready" > /home/psladmin/ready.txt

