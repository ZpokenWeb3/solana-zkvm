FROM nvidia/cuda:12.5.1-cudnn-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    libudev-dev \
    pkg-config \
    protobuf-compiler \
    libssl-dev \
    llvm \
    clang \
    ca-certificates \
    apt-transport-https \
    git \
    screen \
    cuda-toolkit-12-5 \
    && rm -rf /var/lib/apt/lists/*

# Install Docker
RUN apt update && apt-get install -y software-properties-common
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
RUN apt-cache policy docker-ce
RUN apt-get install -y docker-ce

SHELL ["/bin/bash", "-c"]

RUN export CUDA_HOME=/usr/local/cuda-12.5 && \
    export PATH=$CUDA_HOME/bin:$PATH && \
    export LD_LIBRARY_PATH=$CUDA_HOME/lib64:$LD_LIBRARY_PATH && \
    source ~/.bashrc && \
    source ~/.profile

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="$HOME/.cargo/bin:${PATH}"
RUN source ~/.bashrc
RUN rustup update

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash
RUN source ~/.bashrc
ENV PATH="$HOME/.foundry/bin:${PATH}"
RUN foundryup

# Install RiscZero toolchain
RUN curl -L https://risczero.com/install | bash
RUN source ~/.bashrc
ENV PATH="$HOME/.risc0/bin:${PATH}"
RUN rzup

# Install Solana CLI
RUN sh -c "$(curl -sSfL https://release.solana.com/v1.18.18/install)"
RUN export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
RUN source ~/.bashrc

# Install NVM, Node.js, and Yarn
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash \
    && . ~/.nvm/nvm.sh \
    && nvm install 22 \
    && npm install --global yarn

WORKDIR /app

COPY . /app

CMD ["/bin/bash"]