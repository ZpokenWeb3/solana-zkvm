#!/bin/bash

apt install screen

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

# Build tests and receive transaction signature, block hash
yarn
yarn add rpc-websockets@7.0.0
yarn add dotenv
yarn test
