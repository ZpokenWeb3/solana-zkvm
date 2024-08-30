import * as borsh from "borsh";
import assert from "assert";
import * as web3 from "@solana/web3.js";
// Manually initialize variables that are automatically defined in Playground
const PROGRAM_ID = new web3.PublicKey("6vDY3oP53Gz8WFQ2Up58ViMHAxfwykRn7Wgq1E3BGgod");
const connection = new web3.Connection("http://localhost:8899", "confirmed");
const wallet = { keypair: web3.Keypair.generate() };


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
        lamports: 1 * web3.LAMPORTS_PER_SOL,
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

    const recipientBalanceAfterTx = await connection.getBalance(testRecipientKP.publicKey);
    const gameAccountBalanceAfterTx = await connection.getBalance(gameAccountKP.publicKey);

    const winnings = calculateWinnings(gameData.bet_amount);

    const expectedRecipientBalanceWinnings = initialRecipientBalance + winnings;
    const expectedRecipientBalanceLoss = initialRecipientBalance - Number(gameData.bet_amount);

    console.log(`Winnings: ${winnings}`)
    console.log(`Balances of recipient and game account after tx ${recipientBalanceAfterTx}, ${gameAccountBalanceAfterTx}`);

    assert((recipientBalanceAfterTx === expectedRecipientBalanceLoss ) || (recipientBalanceAfterTx === expectedRecipientBalanceWinnings))
    
    const expectedGameBalanceWinnings = initialGameAccountBalance + Number(gameData.bet_amount);
    const expectedGameBalanceLoss = initialGameAccountBalance - winnings;

    assert((gameAccountBalanceAfterTx == expectedGameBalanceLoss) || (gameAccountBalanceAfterTx == expectedGameBalanceWinnings))

    

  });
});
