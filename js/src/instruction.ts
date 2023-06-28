import * as borsh from "borsh";
import { Buffer } from "buffer";
import { PublicKey, TransactionInstruction } from "@solana/web3.js";

/**
 * Get the user's keystore PDA
 * @param programId The Keyring Program ID
 * @param authority The user authority
 * @returns The user's keystore address and bump seed
 */
export function getKeystoreAddress(
  programId: PublicKey,
  authority: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("keystore"), authority.toBuffer()],
    programId
  );
}

/**
 * The instruction discriminators for the Keyring Program
 */
enum KeyringProgramInstruction {
  CreateKeystore,
  AddEntry,
  RemoveEntry,
}

/**
 * Instruction data for the Keyring Program's `CreateKeystore` instruction
 */
export class CreateKeystoreInstruction {
  ixDiscriminator: KeyringProgramInstruction =
    KeyringProgramInstruction.CreateKeystore;
  constructor() {}

  /**
   * Serialize the instruction data
   * @returns The serialized instruction data
   */
  toBuffer(): Buffer {
    const createKeystoreSchema = new Map([
      [
        CreateKeystoreInstruction,
        { kind: "struct", fields: [["ix_discriminator", "u8"]] },
      ],
    ]);
    return Buffer.from(borsh.serialize(createKeystoreSchema, this));
  }

  /**
   * Builds a transaction instruction for the Keyring Program's `CreateKeystore` instruction
   * @param programId The Keyring Program ID
   * @param authority The user authority
   * @returns The transaction instruction
   */
  instruction(
    programId: PublicKey,
    authority: PublicKey
  ): TransactionInstruction {
    const keys = [
      {
        pubkey: getKeystoreAddress(programId, authority)[0],
        isSigner: false,
        isWritable: true,
      },
      { pubkey: authority, isSigner: true, isWritable: false },
    ];
    return new TransactionInstruction({
      programId,
      keys,
      data: this.toBuffer(),
    });
  }
}

/**
 * Instruction data for the Keyring Program's `AddEntry` instruction
 */
export class AddEntryInstruction {
  ixDiscriminator: KeyringProgramInstruction =
    KeyringProgramInstruction.AddEntry;
  addEntryData: Uint8Array;
  constructor(addEntryData: Uint8Array) {
    this.addEntryData = addEntryData;
  }

  /**
   * Serialize the instruction data
   * @returns The serialized instruction data
   */
  toBuffer(): Buffer {
    let x = this.addEntryData.length;
    const addEntrySchema = new Map([
      [
        AddEntryInstruction,
        {
          kind: "struct",
          fields: [
            ["ix_discriminator", "u8"],
            ["add_entry_data", [x]],
          ],
        },
      ],
    ]);
    return Buffer.from(borsh.serialize(addEntrySchema, this));
  }

  /**
   * Builds a transaction instruction for the Keyring Program's `AddEntry` instruction
   * @param programId The Keyring Program ID
   * @param authority The user authority
   * @returns The transaction instruction
   */
  instruction(
    programId: PublicKey,
    authority: PublicKey
  ): TransactionInstruction {
    const keys = [
      {
        pubkey: getKeystoreAddress(programId, authority)[0],
        isSigner: false,
        isWritable: true,
      },
      { pubkey: authority, isSigner: true, isWritable: false },
    ];
    return new TransactionInstruction({
      programId,
      keys,
      data: this.toBuffer(),
    });
  }
}

/**
 * Instruction data for the Keyring Program's `RemoveEntry` instruction
 */
export class RemoveEntryInstruction {
  ixDiscriminator: KeyringProgramInstruction =
    KeyringProgramInstruction.RemoveEntry;
  removeEntryData: Uint8Array;
  constructor(removeEntryData: Uint8Array) {
    this.removeEntryData = removeEntryData;
  }

  /**
   * Serialize the instruction data
   * @returns The serialized instruction data
   */
  toBuffer(): Buffer {
    let x = this.removeEntryData.length;
    const removeEntrySchema = new Map([
      [
        RemoveEntryInstruction,
        {
          kind: "struct",
          fields: [
            ["ix_discriminator", "u8"],
            ["remove_entry_data", [x]],
          ],
        },
      ],
    ]);
    return Buffer.from(borsh.serialize(removeEntrySchema, this));
  }

  /**
   * Builds a transaction instruction for the Keyring Program's `RemoveEntry` instruction
   * @param programId The Keyring Program ID
   * @param authority The user authority
   * @returns The transaction instruction
   */
  instruction(
    programId: PublicKey,
    authority: PublicKey
  ): TransactionInstruction {
    const keys = [
      {
        pubkey: getKeystoreAddress(programId, authority)[0],
        isSigner: false,
        isWritable: true,
      },
      { pubkey: authority, isSigner: true, isWritable: false },
    ];
    return new TransactionInstruction({
      programId,
      keys,
      data: this.toBuffer(),
    });
  }
}
