# Download Ubuntu 24.04 from Microsoft Image Registry
FROM mcr.microsoft.com/mirror/docker/library/ubuntu:24.04

# To build the image, run the following command:
# docker build -t pftnodecontainer .
# docker run  --name remote_server -it -p 58897:22 pftnodeimage -t pftnodecontainer


ARG USER=pftadmin
ARG PEM_KEY=cluster_key.pub
ARG CCF_VERSION="6.0.5"
ARG CCF_PLATFORM="virtual"
ARG SCITT_VERSION="tags/0.14.0"

RUN apt-get update && apt-get install -y \
    build-essential \
    linux-tools-generic \
    linux-tools-common \
    clang \ 
    curl \
    cmake \
    jq \
    llvm \ 
    screen \
    pkg-config \
    python3 \
    python3-pip\
    python3-virtualenv \
    ca-certificates \ 
    protobuf-compiler \
    htop \
    net-tools \ 
    libssl-dev \ 
    librocksdb-dev \
    libprotobuf-dev \ 
    openssh-server \
    tmux \
    rsync \
    git \
    # ccf dependencies start here
    sudo \  
    which \
    procps \
    alien \
    rpm \
    clang-tools \
    ninja-build \
    libuv1-dev \
    libnghttp2-dev \
    libcurl4-openssl-dev \
    python3.12-venv \ 
    lsb-release && \
    curl -LO https://apache.jfrog.io/artifactory/arrow/ubuntu/apache-arrow-apt-source-latest-$(lsb_release -cs).deb && \
    dpkg -i apache-arrow-apt-source-latest-$(lsb_release -cs).deb && \
    apt update && \
    apt install -y libarrow-dev libparquet-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    rm -rf /usr/share/doc /usr/share/man /usr/share/info /usr/share/lintian /usr/share/linda && \
    rm -rf /usr/share/locale/*


RUN curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_PLATFORM}_devel_${CCF_VERSION}_x86_64.rpm" -o ccf.rpm && \
    alien --to-deb ccf.rpm && \
    dpkg -i ./ccf*.deb && \
    rm ./ccf.rpm ./ccf*.deb && \
    apt --fix-broken install -y

RUN git clone https://github.com/microsoft/scitt-ccf-ledger/ /opt/scitt-ccf-ledger && \
    cd /opt/scitt-ccf-ledger && \
    git checkout ${SCITT_VERSION} && \
    # sed -i "s/CCF_APP_INFO/CCF_APP_DEBUG/" app/src/tracing.h && \ 
    sed -i "s/MAX_ACTIVE_HANDLES = 100/MAX_ACTIVE_HANDLES = 1000/" app/src/historical/historical_queries_adapter.h && \
    PLATFORM=${CCF_PLATFORM} BUILD_TESTS=OFF ./build.sh && \    
    python3 -m venv venv && \
    . venv/bin/activate && \
    pip install --disable-pip-version-check -q -e ./pyscitt && \
    pip install --disable-pip-version-check -q wheel && \
    pip install --disable-pip-version-check -q -r test/requirements.txt && \
    pip install ccf==${CCF_VERSION}

COPY resolve.js /tmp/scitt/share/scitt/constitution/resolve.js
# and finish here

RUN git clone https://github.com/scottchiefbaker/dool /opt/dool && \
    cd /opt/dool && \
    git checkout v1.3.4 && \
    make install

# DISABLED: we are not using this atm and it adds more than 1GB to the image size
# Install Azure CLI
# RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Create a new user
RUN useradd -ms /bin/bash ${USER}
# Change password
RUN echo ${USER}:password1234 | chpasswd

# # Add user to sudoers
# RUN usermod -aG sudo ${USER} && \
#     echo "${USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

## Setup SSH (this is not cloud-native, but is necessary to keep consistent with
## the rest of the experiments, which are cloud-native)
## Create ssh directory in home for non-root user
RUN mkdir -p /home/${USER}/.ssh
RUN mkdir -p /var/run/sshd
## Copy the ssh public key in the authorized_keys file.
COPY ${PEM_KEY} /home/${USER}/.ssh/authorized_keys
## change ownership of the key file.
RUN chown -R ${USER}:$GID /home/${USER}/.ssh && \
    chmod 700 /home/${USER}/.ssh && \
    chmod 600 /home/${USER}/.ssh/authorized_keys
## authorize SSH connection with public key 
RUN echo "PubkeyAuthentication yes" > /etc/ssh/sshd_config
## Enable SFTP (necessary for Fabric to work)
RUN echo "Subsystem sftp /usr/lib/openssh/sftp-server" >> /etc/ssh/sshd_config
## Export Port 22 for SSH Connections
EXPOSE 22
## Export Ports For Nodes. TODO(natacha): this is a hack. Currently, opening 50 ports and
## assuming that is enough. 3000 is also currently hardcoded. Will need to fix this. 
EXPOSE 3000-3050
EXPOSE 4000-4050

# DISABLED: same as with azure-cli. we actually install rust in the dev container afterwards
# Get Rust
# RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
# Place Rust in PATH
# ENV PATH = "/home/${USER}/.cargo/bin:${PATH}"

CMD ["/usr/sbin/sshd", "-D"]