import * as borsh from "borsh";
import { Buffer } from "buffer";
import { seq, struct, u8 } from "@solana/buffer-layout";
import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { getKeystoreAddress } from "./state";
import { PROGRAM_ID } from ".";

/**
 * The instruction discriminators for the Keyring Program
 */
enum KeyringProgramInstruction {
  CreateKeystore = 0,
  AddEntry = 1,
  RemoveEntry = 2,
}

/**
 * Instruction data for the Keyring Program's `CreateKeystore` instruction
 */
export interface CreateKeystoreInstructionData {
  instruction: KeyringProgramInstruction.CreateKeystore;
}
export const createKeystoreInstructionData =
  struct<CreateKeystoreInstructionData>([u8("instruction")]);

/**
 * Builds a transaction instruction for the Keyring Program's `CreateKeystore` instruction
 * @param authority The user authority
 * @returns The transaction instruction
 */
export function createCreateKeystoreInstruction(
  authority: PublicKey,
): TransactionInstruction {
  const keys = [
    {
      pubkey: getKeystoreAddress(authority)[0],
      isSigner: false,
      isWritable: true,
    },
    { pubkey: authority, isSigner: true, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];

  const data = Buffer.alloc(createKeystoreInstructionData.span);
  createKeystoreInstructionData.encode(
    { instruction: KeyringProgramInstruction.CreateKeystore },
    data,
  );

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys,
    data,
  });
}

/**
 * Instruction data for the Keyring Program's `AddEntry` instruction
 */
export interface AddEntryInstructionData {
  instruction: KeyringProgramInstruction.AddEntry;
  addEntryData: number[];
}

/**
 * Builds a transaction instruction for the Keyring Program's `AddEntry` instruction
 * @param programId The Keyring Program ID
 * @param authority The user authority
 * @returns The transaction instruction
 */
export function createAddEntryInstruction(
  authority: PublicKey,
  addEntryData: Buffer,
): TransactionInstruction {
  const keys = [
    {
      pubkey: getKeystoreAddress(authority)[0],
      isSigner: false,
      isWritable: true,
    },
    { pubkey: authority, isSigner: true, isWritable: false },
  ];

  const entryDataAsArray = Array.from(addEntryData);
  const span = 1 + addEntryData.length;
  const data = Buffer.alloc(span);
  struct<AddEntryInstructionData>([
    u8("instruction"),
    seq(u8(), entryDataAsArray.length, "addEntryData"),
  ]).encode(
    {
      instruction: KeyringProgramInstruction.AddEntry,
      addEntryData: entryDataAsArray,
    },
    data,
  );

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys,
    data,
  });
}

/**
 * Instruction data for the Keyring Program's `RemoveEntry` instruction
 */
export interface RemoveEntryInstructionData {
  instruction: KeyringProgramInstruction.RemoveEntry;
  removeEntryData: number[];
}

/**
 * Builds a transaction instruction for the Keyring Program's `RemoveEntry` instruction
 * @param programId The Keyring Program ID
 * @param authority The user authority
 * @returns The transaction instruction
 */
export function createRemoveEntryInstruction(
  authority: PublicKey,
  removeEntryData: Buffer,
): TransactionInstruction {
  const keys = [
    {
      pubkey: getKeystoreAddress(authority)[0],
      isSigner: false,
      isWritable: true,
    },
    { pubkey: authority, isSigner: true, isWritable: false },
  ];

  const removeEntryDataAsArray = Array.from(removeEntryData);
  const span = 1 + removeEntryDataAsArray.length;
  const data = Buffer.alloc(span);
  struct<RemoveEntryInstructionData>([
    u8("instruction"),
    seq(u8(), removeEntryDataAsArray.length, "removeEntryData"),
  ]).encode(
    {
      instruction: KeyringProgramInstruction.RemoveEntry,
      removeEntryData: removeEntryDataAsArray,
    },
    data,
  );

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys,
    data,
  });
}
