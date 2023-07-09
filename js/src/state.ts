import { AccountInfo, Connection, PublicKey } from "@solana/web3.js";
import {
  EncryptionAlgorithm,
  fromKeystoreEntrytoEncryptionAlgorithm,
} from "./algorithm";
import { packKeystoreEntry, toBytesFromU32, unpackKeystoreEntry } from "./tlv";
import { PROGRAM_ID } from ".";

/**
 * Get the user's keystore PDA
 * @param programId The Keyring Program ID
 * @param authority The user authority
 * @returns The user's keystore address and bump seed
 */
export function getKeystoreAddress(authority: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("keystore"), authority.toBuffer()],
    PROGRAM_ID,
  );
}

/**
 * Get the user's keystore account
 * @param connection Solana RPC connection
 * @param authority The user authority
 * @returns The user's keystore account
 */
export async function getKeystoreAccount(
  connection: Connection,
  authority: PublicKey,
): Promise<AccountInfo<Buffer>> {
  const [keystoreAddress] = getKeystoreAddress(authority);
  const keystoreAccount = await connection.getAccountInfo(keystoreAddress);
  if (keystoreAccount === null) {
    throw new Error("Keystore account not found");
  }
  return keystoreAccount;
}

/**
 * Get the user's keystore account, unpacked
 * @param connection Solana RPC connection
 * @param authority The user authority
 * @returns The user's keystore account, unpacked
 */
export async function getKeystore(
  connection: Connection,
  authority: PublicKey,
): Promise<Keystore> {
  return unpackKeystore((await getKeystoreAccount(connection, authority)).data);
}

/**
 * Class for managing a TLV structure of keystore entries.
 *
 * The data within a keystore account is managed using nested TLV entries.
 * * T: The new entry discriminator (marks the start of a new keystore entry)
 * * L: The length of the entry
 * * V: The data of the entry
 *     * (Encryption key)
 *         * T: The algorithm discriminator (provided by sRFC workflow)
 *         * L: The length of the key
 *         * V: The key itself
 *     * (Additional configurations)
 *         * T: The configuration discriminator (marks additional
 *           configurations are present)
 *         * L: The total length of the configuration data
 *         * V: The configuration data
 *             * (Configuration: `K, V`)
 *                 * T: The configuration key (provided by sRFC workflow)
 *                 * L: The configuration value length
 *                 * T: The configuration value
 */
export class Keystore {
  entries: EncryptionAlgorithm[];
  constructor(entries: EncryptionAlgorithm[]) {
    this.entries = entries;
  }
}

export function packKeystore(keystore: Keystore): Buffer {
  let offset = 4;
  let data = Buffer.alloc(4);
  data.set(toBytesFromU32(keystore.entries.length));
  for (const entry of keystore.entries) {
    let packData = packKeystoreEntry(entry.toKeystoreEntry());
    let newData = Buffer.alloc(data.length + packData.length);
    newData.set(data, 0);
    newData.set(packData, offset);
    data = newData;
    offset += packData.length;
  }
  return data;
}

export function unpackKeystore(data: Buffer): Keystore {
  let entries: EncryptionAlgorithm[] = [];
  let offset = 4; // Number of entries
  let i = 1;
  while (offset < data.length) {
    let sliceData = data.subarray(offset);
    let [entry, entryEnd] = unpackKeystoreEntry(sliceData);
    entries.push(fromKeystoreEntrytoEncryptionAlgorithm(entry));
    offset += entryEnd;
  }
  return new Keystore(entries);
}
