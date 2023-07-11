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
  EncryptionKeyConfig,
  Keyring,
  Keystore,
  Rsa,
} from "../src";

function getTestCurve25519Key(): EncryptionKeyConfig {
  return new Curve25519(Keypair.generate().publicKey.toBuffer());
}

function getTestRsaKey(): EncryptionKeyConfig {
  let bytes = Buffer.alloc(64);
  bytes.set(Keypair.generate().publicKey.toBuffer(), 0);
  bytes.set(Keypair.generate().publicKey.toBuffer(), 32);
  return new Rsa(bytes);
}

/**
 * Keyring Program Tests
 */
describe("Keyring Program Tests", async () => {
  const connection = new Connection("http://localhost:8899", {
    commitment: "confirmed",
  });
  const authority = Keypair.generate();

  const keyring = new Keyring(connection);

  let testCurve25519Key: EncryptionKeyConfig;
  let testRsaKey: EncryptionKeyConfig;

  async function getFundRentInstruction(
    authority: PublicKey,
    newSpace: number,
  ): Promise<TransactionInstruction> {
    return SystemProgram.transfer({
      fromPubkey: authority,
      toPubkey: keyring.getKeyringAddress(authority)[0],
      lamports: await connection.getMinimumBalanceForRentExemption(newSpace),
    });
  }

  async function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  const sleepTime = 3000;

  /**
   * Fund the authority and set the test keys
   */
  before(async () => {
    console.log("Airdropping...");
    await connection.requestAirdrop(
      authority.publicKey,
      0.5 * LAMPORTS_PER_SOL,
    );
    // sleep 2 seconds
    await sleep(sleepTime);
    testCurve25519Key = getTestCurve25519Key();
    testRsaKey = getTestRsaKey();
  });

  /**
   * Can create a keyring account
   */
  it("Can create a keystore", async () => {
    console.log("Creating keyring...");
    console.log(
      `Keyring Account: ${keyring
        .getKeyringAddress(authority.publicKey)[0]
        .toBase58()}`,
    );
    console.log(`Authority: ${authority.publicKey.toBase58()}`);

    const instruction = keyring.createKeyringInstruction(authority.publicKey);
    const txid = await keyring.processInstructions([instruction], authority, [
      authority,
    ]);
    console.log(`Transaction ID: ${txid}`);

    // sleep 2 seconds
    await sleep(sleepTime);
    // Check to make sure the keystore was created
    await keyring.getKeystore(authority.publicKey);
  });

  /**
   * Can add a key
   */
  it("Can add a key", async () => {
    const newKey = testCurve25519Key;

    const fundRentInstruction = await getFundRentInstruction(
      authority.publicKey,
      newKey.getPackedLength(),
    );

    const instruction = await keyring.addEntryInstruction(
      authority.publicKey,
      newKey,
    );
    const txid = await keyring.processInstructions(
      [fundRentInstruction, instruction],
      authority,
      [authority],
    );
    console.log(`Transaction ID: ${txid}`);

    // sleep 2 seconds
    await sleep(sleepTime);
    // Manually grabbing account to check buffer length
    const keystoreAccount = await keyring.getKeyringAccount(
      authority.publicKey,
    );
    console.log(`Keystore data length: ${keystoreAccount.data.length}`);

    // Check to make sure the key was added
    const keystore = await keyring.getKeystore(authority.publicKey);
    const mockKeystore = new Keystore([testCurve25519Key]);
    assert(
      JSON.stringify(keystore) == JSON.stringify(mockKeystore),
      "Keystores do not match!",
    );
  });

  /**
   * Can add another key
   */
  it("Can add another key", async () => {
    const newKey = testRsaKey;

    const fundRentInstruction = await getFundRentInstruction(
      authority.publicKey,
      newKey.getPackedLength(),
    );

    const instruction = await keyring.addEntryInstruction(
      authority.publicKey,
      newKey,
    );
    const txid = await keyring.processInstructions(
      [fundRentInstruction, instruction],
      authority,
      [authority],
    );
    console.log(`Transaction ID: ${txid}`);

    // sleep 2 seconds
    await sleep(sleepTime);
    // Manually grabbing account to check buffer length
    const keystoreAccount = await keyring.getKeyringAccount(
      authority.publicKey,
    );
    console.log(`Keystore data length: ${keystoreAccount.data.length}`);

    // Check to make sure the key was added
    const keystore = await keyring.getKeystore(authority.publicKey);
    const mockKeystore = new Keystore([testCurve25519Key, testRsaKey]);
    assert(
      JSON.stringify(keystore) == JSON.stringify(mockKeystore),
      "Keystores do not match!",
    );
  });

  /**
   * Can remove a key
   */
  it("Can remove a key", async () => {
    const removeKey = testCurve25519Key;

    const instruction = await keyring.removeEntryInstruction(
      authority.publicKey,
      removeKey,
    );
    const txid = await keyring.processInstructions([instruction], authority, [
      authority,
    ]);
    console.log(`Transaction ID: ${txid}`);

    // sleep 2 seconds
    await sleep(2000);
    // Manually grabbing account to check buffer length
    const keystoreAccount = await keyring.getKeyringAccount(
      authority.publicKey,
    );
    console.log(`Keystore data length: ${keystoreAccount.data.length}`);

    // Check to make sure the key was added
    const keystore = await keyring.getKeystore(authority.publicKey);
    const mockKeystore = new Keystore([testRsaKey]);
    assert(
      JSON.stringify(keystore) == JSON.stringify(mockKeystore),
      "Keystores do not match!",
    );
  });
});
