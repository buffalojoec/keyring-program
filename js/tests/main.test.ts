import assert from "assert";
import { before, describe, it } from "mocha";
import {
  AccountInfo,
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  AddEntryInstruction,
  CreateKeystoreInstruction,
  Curve25519,
  Keystore,
  RemoveEntryInstruction,
  RSA,
  buildTransactionV0,
  getKeystore,
} from "../src";

/**
 * Keyring Program Tests
 */
describe("Keyring Program Tests", async () => {
  const connection = new Connection("http://localhost:8899", "confirmed");
  const authority = Keypair.generate();

  const testCurve25519Keypair = Keypair.generate();
  const testRSAKeypair = Keypair.generate();

  /**
   * Sends a transaction with the provided instruction
   * @param instruction The instruction to send
   */
  async function sendKeystoreTestTransaction(
    instruction: TransactionInstruction
  ): Promise<void> {
    const tx = await buildTransactionV0(
      connection,
      [instruction],
      authority.publicKey,
      [authority]
    );
    const txid = await connection.sendTransaction(tx);
    console.log(`Transaction ID: ${txid}`);
  }

  /**
   * Fund the authority
   */
  before(async () => {
    connection.requestAirdrop(authority.publicKey, 0.05 * LAMPORTS_PER_SOL);
  });

  /**
   * Can create a keystore
   */
  it("Can create a keystore", async () => {
    const instruction = new CreateKeystoreInstruction().instruction(
      authority.publicKey
    );
    await sendKeystoreTestTransaction(instruction);
    // Check to make sure the keystore was created
    await getKeystore(connection, authority.publicKey);
  });

  /**
   * Can add a key
   */
  it("Can add a key", async () => {
    const newEntryData = new Curve25519(
      testCurve25519Keypair.publicKey.toBuffer()
    ).toBuffer();
    const instruction = new AddEntryInstruction(newEntryData).instruction(
      authority.publicKey
    );
    await sendKeystoreTestTransaction(instruction);
    // Check to make sure the key was added
    const keystore = await getKeystore(connection, authority.publicKey);
    const mockKeystore = new Keystore([
      new Curve25519(testCurve25519Keypair.publicKey.toBuffer()),
    ]);
    assert(keystore === mockKeystore, "Keystores do not match!");
  });

  /**
   * Can add another key
   */
  it("Can add another key", async () => {
    const newEntryData = new RSA(
      testRSAKeypair.publicKey.toBuffer()
    ).toBuffer();
    const instruction = new AddEntryInstruction(newEntryData).instruction(
      authority.publicKey
    );
    await sendKeystoreTestTransaction(instruction);
    // Check to make sure the key was added
    const keystore = await getKeystore(connection, authority.publicKey);
    const mockKeystore = new Keystore([
      new Curve25519(testCurve25519Keypair.publicKey.toBuffer()),
      new RSA(testRSAKeypair.publicKey.toBuffer()),
    ]);
    assert(keystore === mockKeystore, "Keystores do not match!");
  });

  /**
   * Can remove a key
   */
  it("Can remove a key", async () => {
    const removeEntryData = new Curve25519(
      testCurve25519Keypair.publicKey.toBuffer()
    ).toBuffer();
    const instruction = new RemoveEntryInstruction(removeEntryData).instruction(
      authority.publicKey
    );
    await sendKeystoreTestTransaction(instruction);
    // Check to make sure the key was removed
    const keystore = await getKeystore(connection, authority.publicKey);
    const mockKeystore = new Keystore([
      new RSA(testRSAKeypair.publicKey.toBuffer()),
    ]);
    assert(keystore === mockKeystore, "Keystores do not match!");
  });
});
