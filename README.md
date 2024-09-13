# Solana transaction execution using zkVM

This project enables the execution of Solana transactions within a zkVM environment, leveraging zero-knowledge proofs to validate transactions and ensure secure, private computation, with the ability to verify this computation on the blockchain.

To better understand the concepts behind this project, check out the [zkVM Overview](https://dev.risczero.com/api/zkvm/)
## Dependencies
First, make sure [rustup](https://rustup.rs/) is installed. The
[`rust-toolchain.toml`](risczero/rust-toolchain.toml) file will be used by `cargo` to
automatically install the correct version.

If you want to test verifier contract install Foundry:
```bash
curl -L https://foundry.paradigm.xyz | bash
```

To install RiscZero toolchain:
```bash
curl -L https://risczero.com/install | bash
rzup
```
You can verify the installation was successful by running:
```
cargo risczero --version
```

> **NOTE:** To test a Solana program, you should install `solana-cli` and `yarn`.


## Quick Start
First, install the RISC Zero toolchain using the instructions [above](#Dependencies).

### Build the code

To build all methods and execute the method within the zkVM, run the following
command:

```bash
cargo build --release
```
Build your Solidity smart contracts

> **NOTE:** cargo build needs to run first to generate the ImageID.sol contract.
```bash
forge build
```

Build Solana program project and start local test validator
```bash
yarn
cd coinflip/program
cargo build-sbf
```
### Run the tests
Start a local test validator to retrieve transactions and accounts from `localhost`:
```bash
solana-test-validator
```
Tests zkVM program.
```bash
cargo run --release --bin host
```
Test Solidity contracts, integrated with your zkVM program.
```bash
forge test -vvv 
```
Producing the Groth16 SNARK proofs for requires running on an x86 machine with Docker installed. Apple silicon is currently unsupported for local proving.

Test Solana coinflip program:
```bash
yarn test
```
Run client
```bash
yarn client
```


## Running the Dockerfile

This section provides instructions on how to build and run the Docker image with GPU acceleration. It includes steps for starting a local validator node, executing transactions, and proving those transactions.

### Prerequisites
Ensure you have Docker installed on your machine. You can download and install Docker from [Docker's official website](https://docs.docker.com/engine/install/ubuntu/).

To enable GPU acceleration, you need to install the NVIDIA Container Toolkit and configure Docker on your machine. You can follow the setup instructions provided in [the following link](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html#configuring-docker).

### Build and runtime
Use the following command to build your Docker image:
```bash
docker build -t solana-cuda-prover .
```
Use the following command to run your Docker container with GPU support:
```bash
sudo docker run -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp --gpus all -it --rm --name solana-cuda-prover solana-cuda-prover bash
```

Use the following commands to run the script that launches a local validator, makes a transaction, and proves the transaction with GPU acceleration:
```bash
chmod +x ./setup-validator.sh
./setup-validator.sh
```

Add your private key to the `.env` file located in the `contracts` folder.
Use the following commands to run the script that executes a transaction on Neon MainNet or DevNet:
```bash
chmod +x ./verify.sh
./verify.sh DEVNET
```
Pass the network parameter as either `MAINNET` or `DEVNET` to the script.

## Deploy Verifier and verification in Neon
### Environment Setup
To configure your environment to use Hardhat, add the following variables to your `.env` file:
```text
# Devnet Configuration
RPC_URL_DEVNET=https://devnet.neonevm.org
CHAIN_ID_DEVNET=245022926

# Mainnet Configuration
RPC_URL_MAINNET=https://neon-proxy-mainnet.solana.p2p.org
CHAIN_ID_MAINNET=245022934

# Verifier URL for Blockscout
VERIFIER_URL_BLOCKSCOUT=https://neon-devnet.blockscout.com/api

# Verifier Addresses
VERIFIER_ADDRESS=
PRIVATE_KEY=""
```
MainNet address: `0xF9dB5cD92fbE2A32D3491f10241C2008Df9ba2Cb`

DevNet address: `0x8406d7D31ffC9bAF8BA7D2fd4965E4EC7Bd93a4d`

After building the Rust project, the ImageID used in the verification process is saved in the `.env` file.

Source your `.env` file:
```bash
source .env
```

### Deployment and Verification Commands
To build the Hardhat project, use the following commands:
```bash
cd contracts
yarn
```
To deploy a new contract on Neon EVM, use the following command:
```bash
npx hardhat run --network neonlabs scripts/deployVerifier.ts
```
Use `neonlabs` for DevNet and `neonmainnet` for MainNet.

To create a verification transaction, run the following command:
```bash
npx hardhat run --network neonlabs scripts/verification.ts
```
## Directory Structure

The project contains a zkVM folder, also known as risczero, and a coinflip folder with a Solana program and TypeScript tests.
```text
solana-zkvm
├── contracts                           <-- [Verifier contract, deploy and verify scripts]   
├── risczero
│   ├── Cargo.toml
│   ├── host
│   │   ├── Cargo.toml
│   │   └── src
│   │       └── main.rs                 <-- [Host code goes here]  
│   └── methods                 
│        ├── Cargo.toml
│        ├── build.rs
│        ├── guest
│        │   ├── Cargo.toml
│        │   └── src
│        │       └── main.rs            <-- [Guest code with transaction execution goes here]
│        ├── core                       <-- [Solana simulator logic goes here]
│        └── src
│            └── lib.rs          
└── coinflip
    ├── tests
    │   └── native.test.ts              <-- [Solana program tests]
    └── program
        ├── Cargo.toml
        └── src
            └── lib.rs                  <-- [Solana program]
```

## Contributing
Any contributions you make are greatly appreciated.
If you have a suggestion that could improve this project, please follow the instructions described  in the [CONTRIBUTING.md](CONTRIBUTING.md)
