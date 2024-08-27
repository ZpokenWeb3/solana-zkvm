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

    function test_Verify() public {
        bytes memory seal = hex"310fe598118e078760fb449f2120f84b12c986151e33f303c47a2d85bca8661ce66c7eb409c525de729ad420982d6bc7e92987857c2d4118f575ec5121eeddb853c48a550a30c0782ad8eaed7d34d2456061f1b977aaa76bb5d2965d88398ce0ca638df91183ae4ef2e70b64a19978c31a370ad45875b04c84f5126090408a1366d7555026c7e7ed47d2f9627fe9be8fd6e773408b820d941e7d051d027ba2fba090044e093a46fa87a5a49e8616e358bc1282be1c51b47b8a43335d8cc60b2d204cfd8e2d98bba4fc4ce1097c650f9437eb258d7592c0572f7b6eab15ed22694d83bbdf243d8cc9a5934e1092d9aadba48ddaf69429b20cae305044420fe99644b9255d";
        bytes memory journal = hex"fb000000220000004900000018000000060000003500000076000000180000002e0000008f0000000e000000c90000003b00000022000000c3000000b3000000e4000000550000004e0000009b00000035000000ec0000000b00000000000000850000005b000000e2000000970000005d000000920000002000000057000000";
        svmVerifier.verify(journal, seal);
    }
}
