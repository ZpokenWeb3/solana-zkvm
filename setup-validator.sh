#!/bin/bash

export PATH=~/.local/share/solana/install/active_release/bin:$PATH

mkdir solana-local-validator
cd solana-local-validator

# Create keypair
output=$(solana-keygen grind --ignore-case --starts-with QN:1)
filename=$(echo "$output" | grep "Wrote keypair to" | awk -F'Wrote keypair to ' '{print $2}')
full_path=$(pwd)
key_path="$full_path/$filename"
solana config set --url localhost --keypair "$key_path"

# Start local validator in screen
SESSION_NAME="solana-validator"
COMMAND="solana-test-validator --limit-ledger-size 100000"
screen -dmS "$SESSION_NAME" bash -c "$COMMAND; exec bash"
echo "Started a new screen session '$SESSION_NAME' running the command: $COMMAND"

echo "Wait to initalize solana-validator..."
sleep 5
# Airdrop account
solana airdrop 100

# Build Solana program
cd ../coinflip/program || exit
cargo build-sbf

# Write deployed PROGRAM_ID and correct path to wallet
output=$(solana program deploy target/deploy/coinflip.so)
program_id=$(echo "$output" | grep "Program Id:" | awk '{print $3}')
echo "ProgramID: $program_id"
cd ../
echo "PROGRAM_ID=$program_id" > .env
echo "WALLET_FILE_PATH='$key_path'" >> .env

# Build tests and input transaction signature, block hash to prover
yarn
yarn add rpc-websockets@7.0.0
yarn add dotenv
yarn test
output=$(yarn test)
block_hash=$(echo "$output" | grep "Blockhash:" | awk -F'Blockhash: ' '{print $2}')
signatures_file_name=$(echo "$output" | grep "File saved to:" | awk -F'File saved to: ' '{print $2}')
signatures_full_path="$(pwd)/$signatures_file_name"
echo "Block hash used: $block_hash"
cd ../risczero

# Enable GPU acceleration if cuda toolkit is installed
if command -v nvidia-smi &> /dev/null && command -v nvcc &> /dev/null; then
    CUDA_FLAG="-F cuda"
else
    CUDA_FLAG=""
fi

RUST_LOG=info cargo run --release --bin host "$CUDA_FLAG" -- --json_rpc_url http://localhost:8899 --block_hash "$block_hash" --transactions_file "$signatures_full_path"

# Verifier part
forge build