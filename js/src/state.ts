import { Connection, PublicKey } from "@solana/web3.js";
import {
  EncryptionAlgorithm,
  fromKeystoreEntrytoEncryptionAlgorithm,
} from "./algorithm";
import { packKeystoreEntry, unpackKeystoreEntry } from "./tlv";

/**
 * The Keyring Program ID
 */
export const PROGRAM_ID: PublicKey = new PublicKey(
  "8Td3Rmp4WHhJj1VCzVvmNuk7cMWjr5QeeQ9ist9dffKw"
);

/**
 * Get the user's keystore PDA
 * @param programId The Keyring Program ID
 * @param authority The user authority
 * @returns The user's keystore address and bump seed
 */
export function getKeystoreAddress(authority: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("keystore"), authority.toBuffer()],
    PROGRAM_ID
  );
}

/**
 * Get the user's keystore account
 * @param connection Solana RPC connection
 * @param authority The user authority
 * @returns The user's keystore account
 */
export async function getKeystore(
  connection: Connection,
  authority: PublicKey
): Promise<Keystore> {
  const [keystoreAddress] = getKeystoreAddress(authority);
  const keystoreAccount = await connection.getAccountInfo(keystoreAddress);
  if (keystoreAccount === null) {
    throw new Error("Keystore account not found");
  }
  return unpackKeystore(keystoreAccount.data);
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

export function packKeystore(keystore: Keystore): Uint8Array {
  let offset = 0;
  let data = new Uint8Array(0);
  for (const entry of keystore.entries) {
    let packData = packKeystoreEntry(entry.toKeystoreEntry());
    data.set(packData, offset);
    offset += packData.length;
  }
  return data;
}

export function unpackKeystore(data: Uint8Array): Keystore {
  let entries: EncryptionAlgorithm[] = [];
  let offset = 0;
  while (offset < data.length) {
    let [entry, entryEnd] = unpackKeystoreEntry(data.slice(offset));
    entries.push(fromKeystoreEntrytoEncryptionAlgorithm(entry));
    offset += entryEnd;
  }
  return new Keystore(entries);
}
