import assert from "assert";
import { before, describe, it } from "mocha";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  Curve25519,
  Keystore,
  RSA,
  buildTransactionV0,
  createAddEntryInstruction,
  createCreateKeystoreInstruction,
  createRemoveEntryInstruction,
  getKeystore,
  getKeystoreAccount,
  getKeystoreAddress,
  packKeystoreEntry,
} from "../src";

/**
 * Keyring Program Tests
 */
describe("Keyring Program Tests", async () => {
  const connection = new Connection("http://localhost:8899", {
    commitment: "confirmed",
  });
  const authority = Keypair.generate();

  const testCurve25519Keypair = Keypair.generate();
  const testRSAKeypair = Keypair.generate();

  /**
   * Sends a transaction with the provided instruction
   * @param instruction The instruction to send
   */
  async function sendKeystoreTestTransaction(
    instructions: TransactionInstruction[],
  ): Promise<void> {
    const tx = await buildTransactionV0(
      connection,
      instructions,
      authority.publicKey,
      [authority],
    );
    const txid = await connection.sendTransaction(tx, { skipPreflight: true });
    console.log(`Transaction ID: ${txid}`);
  }

  async function getFundRentInstruction(
    authority: PublicKey,
    newSpace: number,
  ): Promise<TransactionInstruction> {
    return SystemProgram.transfer({
      fromPubkey: authority,
      toPubkey: getKeystoreAddress(authority)[0],
      lamports: await connection.getMinimumBalanceForRentExemption(newSpace),
    });
  }

  /**
   * Sleep for a given number of milliseconds
   * @param ms The number of milliseconds to sleep
   * @returns A promise that resolves after the given number of milliseconds
   *         have passed
   */
  async function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Fund the authority
   */
  before(async () => {
    console.log("Airdropping...");
    await connection.requestAirdrop(
      authority.publicKey,
      0.5 * LAMPORTS_PER_SOL,
    );
    // sleep 2 seconds
    await sleep(2000);
  });

  /**
   * Can create a keystore
   */
  it("Can create a keystore", async () => {
    console.log("Creating keystore...");
    console.log(
      `Keystore: ${getKeystoreAddress(authority.publicKey)[0].toBase58()}`,
    );
    console.log(`Authority: ${authority.publicKey.toBase58()}`);
    const instruction = createCreateKeystoreInstruction(authority.publicKey);
    await sendKeystoreTestTransaction([instruction]);
    // sleep 2 seconds
    await sleep(2000);
    // Check to make sure the keystore was created
    await getKeystore(connection, authority.publicKey);
  });

  /**
   * Can add a key
   */
  it("Can add a key", async () => {
    const newKey = new Curve25519(testCurve25519Keypair.publicKey.toBuffer());
    const addEntryData = packKeystoreEntry(newKey.toKeystoreEntry());
    console.log(`About to pack ${addEntryData.length} bytes...`);
    const fundRentInstruction = await getFundRentInstruction(
      authority.publicKey,
      addEntryData.length,
    );
    const instruction = createAddEntryInstruction(
      authority.publicKey,
      addEntryData,
    );
    await sendKeystoreTestTransaction([fundRentInstruction, instruction]);
    // sleep 2 seconds
    await sleep(2000);
    // Manually grabbing account to check buffer length
    const keystoreAccount = await getKeystoreAccount(
      connection,
      authority.publicKey,
    );
    console.log(`Keystore data length: ${keystoreAccount.data.length}`);
    // Check to make sure the key was added
    const keystore = await getKeystore(connection, authority.publicKey);
    const mockKeystore = new Keystore([
      new Curve25519(testCurve25519Keypair.publicKey.toBuffer()),
    ]);
    assert(
      JSON.stringify(keystore) == JSON.stringify(mockKeystore),
      "Keystores do not match!",
    );
  });

  /**
   * Can add another key
   */
  it("Can add another key", async () => {
    const newKey = new RSA(testRSAKeypair.publicKey.toBuffer());
    const addEntryData = packKeystoreEntry(newKey.toKeystoreEntry());
    console.log(`About to pack ${addEntryData.length} bytes...`);
    const fundRentInstruction = await getFundRentInstruction(
      authority.publicKey,
      addEntryData.length,
    );
    const instruction = createAddEntryInstruction(
      authority.publicKey,
      addEntryData,
    );
    await sendKeystoreTestTransaction([fundRentInstruction, instruction]);
    // sleep 2 seconds
    await sleep(2000);
    // Manually grabbing account to check buffer length
    const keystoreAccount = await getKeystoreAccount(
      connection,
      authority.publicKey,
    );
    console.log(`Keystore data length: ${keystoreAccount.data.length}`);
    // Check to make sure the key was added
    const keystore = await getKeystore(connection, authority.publicKey);
    const mockKeystore = new Keystore([
      new Curve25519(testCurve25519Keypair.publicKey.toBuffer()),
      new RSA(testRSAKeypair.publicKey.toBuffer()),
    ]);
    assert(
      JSON.stringify(keystore) == JSON.stringify(mockKeystore),
      "Keystores do not match!",
    );
  });

  /**
   * Can remove a key
   */
  it("Can remove a key", async () => {
    const removeKey = new Curve25519(
      testCurve25519Keypair.publicKey.toBuffer(),
    );
    const removeEntryData = packKeystoreEntry(removeKey.toKeystoreEntry());
    console.log(`About to remove ${removeEntryData.length} bytes...`);
    const instruction = createRemoveEntryInstruction(
      authority.publicKey,
      removeEntryData,
    );
    await sendKeystoreTestTransaction([instruction]);
    // sleep 2 seconds
    await sleep(2000);
    // Check to make sure the key was removed
    const keystore = await getKeystore(connection, authority.publicKey);
    const mockKeystore = new Keystore([
      new RSA(testRSAKeypair.publicKey.toBuffer()),
    ]);
    assert(
      JSON.stringify(keystore) == JSON.stringify(mockKeystore),
      "Keystores do not match!",
    );
  });
});
