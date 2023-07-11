import {
  AccountInfo,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { EncryptionKeyConfig, Keystore } from "./keystore";
import { seq, struct, u8 } from "@solana/buffer-layout";

/**
 * Keyring Program instructions
 */
enum KeyringInstruction {
  CreateKeyring = 0,
  UpdateKeyring = 1,
}

/**
 * Data for `CreateKeyring` instruction
 */
interface CreateKeyringInstructionData {
  instruction: KeyringInstruction;
}

/**
 * Data for `UpdateKeyring` instruction
 */
interface UpdateKeyringInstructionData {
  instruction: KeyringInstruction;
  data: number[];
}

/**
 * The Keyring Program Client
 */
export class Keyring {
  readonly programId = new PublicKey(
    "4UucrowYQqM6yHeRgoMW2HB2998W9cnVS6tx6nPMdpVn",
  );
  connection: Connection;

  constructor(connection: Connection) {
    this.connection = connection;
  }

  /**
   * Get the user's keyring address
   * @param authority The user authority
   * @returns The keyring address and bump seed
   */
  getKeyringAddress(authority: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("keyring"), authority.toBuffer()],
      this.programId,
    );
  }

  /**
   * Fetch the user's keyring account
   * @param authority The user authority
   * @returns The keyring account
   */
  async getKeyringAccount(authority: PublicKey): Promise<AccountInfo<Buffer>> {
    const [keyringAddress] = this.getKeyringAddress(authority);
    const keyringAccount = await this.connection.getAccountInfo(keyringAddress);
    if (keyringAccount === null) {
      throw new Error("Keyring account not found");
    }
    return keyringAccount;
  }

  /**
   * Fetch the user's keyring account, unpacked
   * @param authority The user authority
   * @returns The keyring account unpacked as a `Keystore`
   */
  async getKeystore(authority: PublicKey): Promise<Keystore> {
    return Keystore.deserialize((await this.getKeyringAccount(authority)).data);
  }

  /**
   * Construct a transaction from a list of instructions
   * @param instructions The instructions to include in the transaction
   * @param payer The transaction fee payer
   * @param signers The transaction signers
   * @returns The transaction
   */
  async buildTransaction(
    instructions: TransactionInstruction[],
    payer: PublicKey,
    signers: Keypair[],
  ): Promise<VersionedTransaction> {
    let blockhash = await this.connection
      .getLatestBlockhash()
      .then((res) => res.blockhash);

    const messageV0 = new TransactionMessage({
      payerKey: payer,
      recentBlockhash: blockhash,
      instructions,
    }).compileToV0Message();

    const tx = new VersionedTransaction(messageV0);
    signers.forEach((s) => tx.sign([s]));

    return tx;
  }

  /**
   * Process a transaction from a list of instructions
   * @param instructions The instructions to include in the transaction
   * @param payer The transaction fee payer
   * @param signers The transaction signers
   * @returns The transaction signature
   */
  async processInstructions(
    instructions: TransactionInstruction[],
    payer: Keypair,
    signers: Keypair[],
  ): Promise<string> {
    const tx = await this.buildTransaction(
      instructions,
      payer.publicKey,
      signers,
    );
    return this.connection.sendRawTransaction(tx.serialize());
  }

  /**
   * Create a `CreateKeyring` instruction
   * @param authority The user authority
   * @returns A `CreateKeyring` instruction
   */
  createKeyringInstruction(authority: PublicKey): TransactionInstruction {
    const [keyringAddress] = this.getKeyringAddress(authority);

    const data = Buffer.alloc(1);

    struct<CreateKeyringInstructionData>([u8("instruction")]).encode(
      {
        instruction: KeyringInstruction.CreateKeyring,
      },
      data,
    );

    return new TransactionInstruction({
      keys: [
        { pubkey: keyringAddress, isSigner: false, isWritable: true },
        { pubkey: authority, isSigner: true, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      programId: this.programId,
      data,
    });
  }

  /**
   * Create an `UpdateKeyring` instruction for adding an entry.
   * Automatically creates the necessary instruction data for adding a new key entry.
   * @param authority The user authority
   * @param entry The new key to add
   * @returns An `UpdateKeyring` instruction
   */
  async addEntryInstruction(
    authority: PublicKey,
    entry: EncryptionKeyConfig,
  ): Promise<TransactionInstruction> {
    const [keyringAddress] = this.getKeyringAddress(authority);
    const keystore = await this.getKeystore(authority);

    keystore.entries.push(entry);

    const newKeyringData = keystore.serialize();
    const newKeyringDataLength = newKeyringData.length;
    const data = Buffer.alloc(1 + newKeyringDataLength);

    struct<UpdateKeyringInstructionData>([
      u8("instruction"),
      seq(u8(), newKeyringDataLength, "data"),
    ]).encode(
      {
        instruction: KeyringInstruction.UpdateKeyring,
        data: Array.from(newKeyringData),
      },
      data,
    );

    return new TransactionInstruction({
      keys: [
        { pubkey: keyringAddress, isSigner: false, isWritable: true },
        { pubkey: authority, isSigner: true, isWritable: false },
      ],
      programId: this.programId,
      data,
    });
  }

  /**
   * Create an `UpdateKeyring` instruction for removing an entry.
   * Automatically creates the necessary instruction data for removing a new key entry.
   * @param authority The user authority
   * @param entry The key to remove
   * @returns An `UpdateKeyring` instruction
   */
  async removeEntryInstruction(
    authority: PublicKey,
    entry: EncryptionKeyConfig,
  ): Promise<TransactionInstruction> {
    const [keyringAddress] = this.getKeyringAddress(authority);
    const keystore = await this.getKeystore(authority);

    const newKeystore = new Keystore(
      keystore.entries.filter(
        (e) => JSON.stringify(e) !== JSON.stringify(entry),
      ),
    );

    const newKeyringData = newKeystore.serialize();
    const newKeyringDataLength = newKeyringData.length;
    const data = Buffer.alloc(1 + newKeyringDataLength);

    struct<UpdateKeyringInstructionData>([
      u8("instruction"),
      seq(u8(), newKeyringDataLength, "data"),
    ]).encode(
      {
        instruction: KeyringInstruction.UpdateKeyring,
        data: Array.from(newKeyringData),
      },
      data,
    );

    return new TransactionInstruction({
      keys: [
        { pubkey: keyringAddress, isSigner: false, isWritable: true },
        { pubkey: authority, isSigner: true, isWritable: false },
      ],
      programId: this.programId,
      data,
    });
  }
}
