import {ethers} from "hardhat";
import crypto from 'crypto';
import {delay} from "@nomiclabs/hardhat-etherscan/dist/src/etherscan/EtherscanService";

require('dotenv').config();

import fs from 'fs';

function generateSHA256Hash(data: string): string {
    const buffer = Buffer.from(data.replace(/^0x/, ''), 'hex');
    return '0x' + crypto.createHash('sha256').update(buffer).digest('hex');
}

async function main() {
    let path = process.env.LATEST_PROOF_PATH;
    let imageID = process.env.IMAGE_ID;

    let fileData = fs.readFileSync(path, 'utf-8');
    let dataParsed = JSON.parse(fileData);
    let seal = dataParsed.seal;
    let journal = dataParsed.journal;

    const verifierAddress = process.env.VERIFIER_ADDRESS;
    const verifierFactory = await ethers.getContractFactory("RiscZeroGroth16Verifier");

    let hashedJournal = generateSHA256Hash(journal);
    let verifier = await verifierFactory.attach(verifierAddress);

    try {
        let result = await verifier.verify(seal, imageID, hashedJournal);
        await delay(20000);
        console.log("Verification succeeded:", result);
    } catch (error) {
        console.error("Verification failed:", error);
    }

}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});