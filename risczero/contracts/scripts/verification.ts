import {ethers} from "hardhat";
import {delay} from "@nomiclabs/hardhat-etherscan/dist/src/etherscan/EtherscanService";

require('dotenv').config();

const fs = require('fs');

async function main() {
    let path = process.env.PROOF_PATH;

    let fileData = fs.readFileSync(path, 'utf-8');
    let dataParsed = JSON.parse(fileData);
    let seal = dataParsed.seal;
    let journal = dataParsed.journal;

    const verifierAddress = process.env.SVM_VERIFIER_ADDRESS;
    const verifierFactory = await ethers.getContractFactory("SvmVerifier");
    let verifier = await verifierFactory.attach(verifierAddress);

    try {
        let result = await verifier.verify(journal, seal);
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