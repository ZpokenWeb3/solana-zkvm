FROM nvidia/cuda:12.5.1-runtime-ubuntu22.04

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
    git \
    screen \
    cuda-toolkit-12-5 \
    && rm -rf /var/lib/apt/lists/*

# Install Docker
RUN apt update && apt-get install -y software-properties-common
RUN apt update && apt-get install -y apt-transport-https ca-certificates curl software-properties-common
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
ENV PATH="/root/.cargo/bin:${PATH}"
RUN source ~/.bashrc
RUN rustup update

# Install RiscZero toolchain
RUN curl -L https://risczero.com/install | bash
RUN source ~/.bashrc
ENV PATH="~/.risc0/bin:${PATH}"
RUN rzup install

# Install Solana CLI
RUN sh -c "$(curl -sSfL https://release.solana.com/v1.18.18/install)"
RUN export PATH="~/.local/share/solana/install/active_release/bin:$PATH"
RUN source ~/.bashrc

# Install NVM, Node.js, and Yarn
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash \
    && . ~/.nvm/nvm.sh \
    && nvm install 22 \
    && npm install --global yarn

# Install Foundry and copy project files
WORKDIR /app
RUN cargo install --git https://github.com/foundry-rs/foundry --profile release --locked forge chisel anvil
COPY . /app

# Build prover binary with GPU feature
WORKDIR /app/risczero
RUN cargo build --release -F cuda

# Remove unused files
WORKDIR /app
RUN cp -r risczero/* ./
RUN rm -r host/ Cargo.toml Cargo.lock solana/ risczero/
RUN cp target/release/host .
RUN rm -r target/

CMD ["/bin/bash"]
