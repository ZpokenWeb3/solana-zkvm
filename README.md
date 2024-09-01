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




## Directory Structure

The project contains a zkVM folder, also known as risczero, and a coinflip folder with a Solana program and TypeScript tests.
```text
solana-zkvm
├── risczero
│   ├── Cargo.toml
│   ├── contracts                       <-- [Verifier contract and generated program digest]
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