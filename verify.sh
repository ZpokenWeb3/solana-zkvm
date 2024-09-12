#!/bin/bash

# Check if an argument is provided
if [ $# -eq 0 ]; then
    echo "No arguments of NEON RPC provided. Usage: $0 MAINNET|DEVNET"
    exit 1
fi

NETWORK=$1

if [ "$NETWORK" == "MAINNET" ]; then
    NETWORK_ENV=neonmainnet
    VERIFIER_ADDRESS=0x4a106670Ef300d21161CFAB20c1C06683Bf08bD2
elif [ "$NETWORK" == "DEVNET" ]; then
    NETWORK_ENV=neonlabs
    VERIFIER_ADDRESS=0x4a106670Ef300d21161CFAB20c1C06683Bf08bD2
else
    echo "Invalid input. Please enter MAINNET or DEVNET."
    exit 1
fi

echo "Network environment set to: $NETWORK_ENV"

# Check if running in Docker
is_docker() {
  if [ -f /.dockerenv ] || grep -q 'docker' /proc/1/cgroup; then
    return 0
  else
    return 1
  fi
}

if is_docker; then
  cd contracts
else
  cd risczero/contracts
fi

ENV_VARS="
RPC_URL_DEVNET=https://devnet.neonevm.org
CHAIN_ID_DEVNET=245022926
RPC_URL_MAINNET=https://neon-proxy-mainnet.solana.p2p.org
CHAIN_ID_MAINNET=245022934
VERIFIER_URL_BLOCKSCOUT=https://neon-devnet.blockscout.com/api
"

ENV_FILE=".env"

# Function to add or update a variable
add_or_update() {
    local var="$1"
    local file="$2"
    local key=$(echo "$var" | cut -d '=' -f 1)
    local value=$(echo "$var" | cut -d '=' -f 2-)

    if grep -q "^${key}=" "$file"; then
        perl -i -pe "s/^${key}=.*/${var}/" "$file"
    else
        # Append the new key
        echo "$var" >> "$file"
    fi
}

# Function to add a variable if it does not already exist
add_if_not_exists() {
    local var="$1"
    local file="$2"

    local key=$(echo "$var" | cut -d '=' -f 1)

    if ! grep -q "^${key}=" "$file"; then
        echo "$var" >> "$file"
    fi
}


if [ -f "$ENV_FILE" ]; then
    for var in $ENV_VARS; do
        add_if_not_exists "$var" "$ENV_FILE"
    done
else
    echo "$ENV_VARS" > "$ENV_FILE"
fi

add_or_update "VERIFIER_ADDRESS=$VERIFIER_ADDRESS" "$ENV_FILE"

source .env
yarn
npx hardhat run --network $NETWORK_ENV scripts/verification.ts