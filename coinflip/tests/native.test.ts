import * as borsh from "borsh";
import assert from "assert";
import * as web3 from "@solana/web3.js";
import {Keypair} from "@solana/web3.js";
import * as fs from "node:fs";
import * as path from "node:path";
import * as dotenv from "dotenv";
import {v4 as uuidv4} from 'uuid';

dotenv.config();

// Manually initialize variables that are automatically defined in Playground
const connection = new web3.Connection("http://localhost:8899", "confirmed");

const loadWalletFromFile = (filePath: string): Keypair => {
    const secretKeyString = fs.readFileSync(filePath, 'utf8');
    const secretKeyArray = JSON.parse(secretKeyString) as number[];
    return Keypair.fromSecretKey(new Uint8Array(secretKeyArray));
}

const PROGRAM_ID = new web3.PublicKey(process.env.PROGRAM_ID || '');

const walletFilePath = path.join(process.env.WALLET_FILE_PATH || '');

// Load the wallet
const wallet = {
    keypair: loadWalletFromFile(walletFilePath)
};

class GameData {
    is_initialized: boolean;
    bet_amount: BigInt;

    constructor(fields: { is_initialized: boolean; bet_amount: BigInt }) {
        this.is_initialized = fields.is_initialized;
        this.bet_amount = fields.bet_amount;
    }
}

const GameSchema = new Map([
    [
        GameData,
        {
            kind: "struct",
            fields: [
                ["is_initialized", "u8"],
                ["bet_amount", "u64"],
            ],
        },
    ],
]);


const serializeGameData = (gameData: GameData): Buffer => {
    const serializedData = borsh.serialize(GameSchema, gameData);
    return Buffer.from(serializedData);
}

const calculateWinnings = (betAmount: BigInt): number => {
    const betAmountFloat = Number(betAmount); // Convert to a number for floating-point operations
    const result = betAmountFloat * 0.95; // Apply a 5% fee
    return Number(Math.round(result)); // Round and convert back to number
};


function createDirectoryIfNotExists(dirPath: string): void {
    if (!fs.existsSync(dirPath)) {
        fs.mkdir(dirPath, {recursive: true}, (err) => {
            if (err) {
                console.error('Error creating directory:', err);
            } else {
                console.log('Directory created successfully:', dirPath);
            }
        });
    } else {
        console.log('Directory already exists:', dirPath);
    }
}

function writeJsonToFile(data: any): void {
    const baseFolder = 'signatures';
    createDirectoryIfNotExists(baseFolder)
    const randomName = uuidv4();
    const filePath = `${baseFolder}/${randomName}.json`;
    const jsonString = JSON.stringify(data, null, 2);
    fs.writeFile(filePath, jsonString, 'utf8', (err) => {
        if (err) {
            console.error('Error writing file:', err);
        } else {
            console.log('File saved to:', filePath);
        }
    });
}

describe("Test", () => {
    const testRecipientKP = web3.Keypair.generate();
    const gameAccountKP = web3.Keypair.generate();

    const gameData = new GameData({
        is_initialized: true,
        bet_amount: BigInt(100_000),
    });
    const serializedData = serializeGameData(gameData);
    const DATA_SIZE = serializedData.length;

    it('Create two accounts for the following test', async () => {

        await connection.requestAirdrop(wallet.keypair.publicKey, 2 * 10 ** 9);

        const ix = (pubkey: web3.PublicKey) => {
            return web3.SystemProgram.createAccount({
                fromPubkey: wallet.keypair.publicKey,
                newAccountPubkey: pubkey,
                space: DATA_SIZE,
                lamports: web3.LAMPORTS_PER_SOL,
                programId: PROGRAM_ID,
            });
        };

        const initTx = new web3.Transaction();
        initTx.add(ix(testRecipientKP.publicKey));
        initTx.add(ix(gameAccountKP.publicKey));

        await web3.sendAndConfirmTransaction(connection, initTx, [
            wallet.keypair,
            testRecipientKP,
            gameAccountKP
        ]);
    });

    it('Transfer between accounts using our program', async () => {
        const initialRecipientBalance = await connection.getBalance(testRecipientKP.publicKey);
        const initialGameAccountBalance = await connection.getBalance(gameAccountKP.publicKey);

        console.log(`Balances of recipient and game account: ${initialRecipientBalance}, ${initialGameAccountBalance}`)

        const gameIx = new web3.TransactionInstruction({
            keys: [
                {
                    pubkey: gameAccountKP.publicKey,
                    isSigner: false,
                    isWritable: true,
                },
                {
                    pubkey: testRecipientKP.publicKey,
                    isSigner: true,
                    isWritable: true,
                },
            ],
            programId: PROGRAM_ID,
            data: serializedData
        });

        const gameTx = new web3.Transaction();
        gameTx.add(gameIx);

        const gameTxHash = await web3.sendAndConfirmTransaction(connection, gameTx, [
            wallet.keypair,
            testRecipientKP,
        ]);

        console.log(`Game tx hash: ${gameTxHash}`);

        const txDetails = await connection.getParsedTransaction(gameTxHash, {commitment: 'confirmed'});
        const block = await connection.getBlock(txDetails.slot, {commitment: 'confirmed'});
        console.log(`Blockhash: ${block.blockhash}`)

        const recipientBalanceAfterTx = await connection.getBalance(testRecipientKP.publicKey);
        const gameAccountBalanceAfterTx = await connection.getBalance(gameAccountKP.publicKey);

        const winnings = calculateWinnings(gameData.bet_amount);

        const expectedRecipientBalanceWinnings = initialRecipientBalance + winnings;
        const expectedRecipientBalanceLoss = initialRecipientBalance - Number(gameData.bet_amount);

        console.log(`Winnings: ${winnings}`)
        console.log(`Balances of recipient and game account after tx ${recipientBalanceAfterTx}, ${gameAccountBalanceAfterTx}`);

        assert((recipientBalanceAfterTx === expectedRecipientBalanceLoss) || (recipientBalanceAfterTx === expectedRecipientBalanceWinnings))

        const expectedGameBalanceWinnings = initialGameAccountBalance + Number(gameData.bet_amount);
        const expectedGameBalanceLoss = initialGameAccountBalance - winnings;

        assert((gameAccountBalanceAfterTx == expectedGameBalanceLoss) || (gameAccountBalanceAfterTx == expectedGameBalanceWinnings))
        writeJsonToFile([gameTxHash]);
    });
});
