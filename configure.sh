#!/bin/bash
USER_HOME=$(eval echo ~$USER)
BASHRC_FILE="$USER_HOME/.bashrc"

apt-get install -y libudev-dev pkg-config protobuf-compiler

# Download and run the Foundry installation script
curl -L https://foundry.paradigm.xyz | bash
source $BASHRC_FILE
foundryup

# Download and install RiscZero toolchain
curl -L https://risczero.com/install | bash
source $BASHRC_FILE
rzup

# Download and install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/v1.18.18/install)"
export PATH="$USER_HOME/.local/share/solana/install/active_release/bin:$PATH"

# Install NodeJs and yarn
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
apt-get install -y nodejs
npm install --global yarn
