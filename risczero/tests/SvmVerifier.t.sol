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
        bytes memory seal = hex"310fe59819024526bbf4417dd2c6f97bac6945795ff3fc6c6f4bc10e901108c0655d03601bda37112ffae02dc11fe21eb1c23e00d005c23eb0b57cc66bed70692253d0c40b0efcdf8fffde1289b853d75f4c9536da6a02b20edd9002e4c2d522df0635412a3d6b63350a1d1641bbf5f1a4fecea50615fdde4b5e8954c830fa4955c1a4ae2bfd0382b67623b3f9011b5303f312486c5f29e10526298048c26e20e32f035d21c7f402104da79236a87b3cc348fd6dcbe81bd8e5675e918e38729fc886e2b011488dc2f780e8163f6d9fb6fad9d328c59b07a24806ea68d941e48f7765129c29f05dc5d20c883d7205fb6674d2d9c0a8071543fe30b4bd8df4d2c5015b9a64";
        bytes memory journal = hex"fb000000220000004900000018000000060000003500000076000000180000002e0000008f0000000e000000c90000003b00000022000000c3000000b3000000e4000000550000004e0000009b00000035000000ec0000000b00000000000000850000005b000000e2000000970000005d000000920000002000000057000000";
        svmVerifier.verify(journal, seal);
    }
}
