import assert from "assert";
import { before, describe, it } from "mocha";
import {
  AccountInfo,
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  AddEntryInstruction,
  CreateKeystoreInstruction,
  RemoveEntryInstruction,
  buildTransactionV0,
  getKeystoreAddress,
} from "../src";

/**
 * Keyring Program Tests
 */
describe("Keyring Program Tests", async () => {
  const connection = new Connection("http://localhost:8899", "confirmed");
  const authority = Keypair.generate();
  const programId = new PublicKey("");

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
   * Gets the keystore account and checks that it exists
   */
  async function getKeystoreChecked(): Promise<AccountInfo<Buffer>> {
    const keystoreAddress = getKeystoreAddress(
      programId,
      authority.publicKey
    )[0];
    const keystoreAccount = await connection.getAccountInfo(keystoreAddress);
    assert(keystoreAccount !== null, "Keystore account was null");
    return keystoreAccount;
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
      programId,
      authority.publicKey
    );
    await sendKeystoreTestTransaction(instruction);
    // Check to make sure the keystore was created
    await getKeystoreChecked();
  });

  /**
   * Can add a key
   */
  it("Can add a key", async () => {
    const newEntryData = Uint8Array.from([1, 2, 3, 4, 5]); // TODO
    const instruction = new AddEntryInstruction(newEntryData).instruction(
      programId,
      authority.publicKey
    );
    await sendKeystoreTestTransaction(instruction);
    // Check to make sure the key was added
    const keystoreAccount = await getKeystoreChecked();
  });

  /**
   * Can add another key
   */
  it("Can add another key", async () => {
    const newEntryData = Uint8Array.from([1, 2, 3, 4, 5]); // TODO
    const instruction = new AddEntryInstruction(newEntryData).instruction(
      programId,
      authority.publicKey
    );
    await sendKeystoreTestTransaction(instruction);
    // Check to make sure the key was added
    const keystoreAccount = await getKeystoreChecked();
  });

  /**
   * Can remove a key
   */
  it("Can remove a key", async () => {
    const removeEntryData = Uint8Array.from([1, 2, 3, 4, 5]); // TODO
    const instruction = new RemoveEntryInstruction(removeEntryData).instruction(
      programId,
      authority.publicKey
    );
    await sendKeystoreTestTransaction(instruction);
    // Check to make sure the key was removed
    const keystoreAccount = await getKeystoreChecked();
  });
});
