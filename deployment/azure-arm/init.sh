#!/bin/bash

set -e

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting VM initialization..."

sudo apt-get update
sudo apt-get install -y ca-certificates curl jq net-tools

log "Setting up Docker..."
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

log "Installing Docker..."
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker pftadmin
sudo systemctl enable docker.service
sudo systemctl enable containerd.service

log "Installing dependencies..."
sudo apt-get install -y screen tmux build-essential cmake clang llvm pkg-config
sudo apt-get install -y protobuf-compiler
sudo apt-get install -y libssl-dev librocksdb-dev libprotobuf-dev
sudo apt-get install -y python3-pip python3-virtualenv

log "Installing kernel tools (may require reboot)..."
sudo apt-get install -y linux-tools-common linux-tools-generic || {
    log "Warning: Failed to install some linux-tools packages, continuing..."
}
KERNEL_VERSION=$(uname -r)
log "Attempting to install linux-tools for kernel $KERNEL_VERSION..."
sudo apt-get install -y "linux-tools-$KERNEL_VERSION" || {
    log "Warning: Could not install linux-tools for current kernel version, continuing..."
}

log "Checking SSH daemon status..."
if ! sudo systemctl is-active --quiet ssh; then
    log "SSH daemon is not active, restarting..."
    sudo systemctl restart ssh
fi

echo -e "*\tsoft\tnofile\t50000\n*\thard\tnofile\t50000" | sudo tee -a /etc/security/limits.conf > /dev/null

log "Installing dool..."
git clone https://github.com/scottchiefbaker/dool /opt/dool && \
cd /opt/dool && \
git checkout v1.3.4 && \
make install

# Mount the data disk
# sudo mkfs.ext4 /dev/sdc
# sudo mkdir /data
# sudo mount /dev/sdc /data
# sudo chmod -R 777 /data

log "VM initialization completed successfully!"