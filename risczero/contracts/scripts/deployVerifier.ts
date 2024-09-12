import { ethers } from "hardhat";
import fs from "node:fs";
require('dotenv').config();

function updateEnvFile(filePath: string, address: string, parameter: string) {
    let content = '';
    if (fs.existsSync(filePath)) {
        content = fs.readFileSync(filePath, 'utf8');
    }

    const lines = content.split('\n');

    let addressLineExists = false;
    const updatedLines = lines.map(line => {
        if (line.startsWith(`${parameter}=`)) {
            addressLineExists = true;
            return `${parameter}=${address}`;
        }
        return line;
    });

    if (!addressLineExists) {
        updatedLines.push(`${parameter}=${address}`);
    }

    const updatedContent = updatedLines.join('\n') + '\n';
    fs.writeFileSync(filePath, updatedContent, { flag: 'w' });
}

async function main() {
    const RiscZeroGroth16VerifierFactory = await ethers.getContractFactory("RiscZeroGroth16Verifier");
    const CONTROL_ROOT = "0x8b6dcf11d463ac455361b41fb3ed053febb817491bdea00fdb340e45013b852e";
    const BN254_CONTROL_ID = "0x05a022e1db38457fb510bc347b30eb8f8cf3eda95587653d0eac19e1f10d164e";
    const verifier = await RiscZeroGroth16VerifierFactory.deploy(CONTROL_ROOT, BN254_CONTROL_ID);
    await verifier.deployed();

    console.log("RiscZeroGroth16Verifier deployed to:", verifier.address);
    updateEnvFile('.env', verifier.address, 'VERIFIER_ADDRESS');
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});