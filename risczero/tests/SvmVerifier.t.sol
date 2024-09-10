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

import {RiscZeroCheats} from "risc0/test/RiscZeroCheats.sol";
import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {SvmVerifier} from "../contracts/SvmVerifier.sol";
import {Elf} from "./Elf.sol"; // auto-generated contract after running `cargo build`.

contract SvmVerifierTest is RiscZeroCheats, Test {
    SvmVerifier public svmVerifier;

    function setUp() public {
        IRiscZeroVerifier verifier = deployRiscZeroVerifier();
        svmVerifier = new SvmVerifier(verifier);
    }

    function testSuccessfulVerifier() public {
        bytes memory seal = hex"50bd1769076fe341fad9b3a1f6b752d86f36f4821b2d85dc22935faaac4858aab14ba70d087aa5e68274ffba6fc9cb969638b5621df0f55e6230e5daa248e1eb00c817fa1ad7b78e94f1061ddb93979339fbffdee23a6a90eff434b4b47db08b41f8bc7f130b28adc78b35abc6b2f02ec6a48481ab88ec1a8468dcde360a16d92158fefd118cd11fa31ee40181737755ccd9ef14358e54847ed6be1fceecffa5a6e4b0b40a6e4a477e3ca2c45be5dcd5e543d82d0504f6d66168020eecbd3e93765044460728f6acb82e7cffc19f08711d75115c6e3c6d951606cc291148c39d98afc77608b81a3de624742e9a3715b99a57a09a8e9c2f8f8733c8ed70b6be646cd1bbd8";
        bytes memory journal = hex"17000000bb0000005d000000930000006a0000007700000033000000d9000000ce000000e0000000100000006a000000ff000000880000000000000031000000f4000000fc000000b1000000360000004a0000002f0000004f000000ec0000003900000003000000120000004a000000f4000000ca0000000f000000b5000000";
        svmVerifier.verify(journal, seal);
    }
}
