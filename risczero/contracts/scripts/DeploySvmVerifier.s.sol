// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import "forge-std/Test.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";
import {RiscZeroGroth16Verifier} from "../src/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "../src/groth16/ControlID.sol";

import {SvmVerifier} from "../src/SvmVerifier.sol";

/// @notice Deployment script for the RISC Zero project.
/// @dev Use the following environment variable to control the deployment:
///     * Set one of these two environment variables to control the deployment wallet:
///         * ETH_WALLET_PRIVATE_KEY private key of the wallet account.
///         * ETH_WALLET_ADDRESS address of the wallet account.
///
/// See the Foundry documentation for more information about Solidity scripts,
/// including information about wallet options.
///
/// https://book.getfoundry.sh/tutorials/solidity-scripting
/// https://book.getfoundry.sh/reference/forge/forge-script
contract SvmVerifierDeploy is Script {

    IRiscZeroVerifier verifier;

    function run() external {
        // Read and log the chainID
        uint256 chainId = block.chainid;
        console2.log("You are deploying on ChainID %d", chainId);

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the verifier, if not already deployed.
        if (address(verifier) == address(0)) {
            verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
            console2.log("Deployed RiscZeroGroth16Verifier to", address(verifier));
        } else {
            console2.log("Using IRiscZeroVerifier contract deployed at", address(verifier));
        }


        // Deploy the application contract.
        SvmVerifier svmVerifier = new SvmVerifier(verifier);
        console2.log("Deployed SvmVerifier to", address(svmVerifier));

        vm.stopBroadcast();
    }
}
