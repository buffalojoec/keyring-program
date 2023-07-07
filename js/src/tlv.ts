import { Buffer } from "buffer";
import {
  HAS_CONFIGURATIONS_DISCRIMINATOR,
  KEYSTORE_ENTRY_DISCRIMINATOR,
  NO_CONFIGURATIONS_DISCRIMINATOR,
} from "./algorithm";

/**
 * Converts a number to a Buffer for a u32
 * @param num A u32 number
 * @returns Buffer
 */
function toBytesFromU32(num: number): Buffer {
  let data = Buffer.alloc(4);
  data.writeUInt32LE(num, 0);
  return data;
}

/**
 * Converts a Buffer to a number for a u32
 * @param bytes The bytes to convert
 * @returns Number for the u32
 */
function toU32FromBytes(bytes: Buffer): number {
  return bytes.readUInt32LE();
}

/**
 * Configurations section in a keystore entry
 *
 * Note: This section is identified by it's unique TLV discriminator,
 * derived from the `SplDiscriminate` macro
 */
export type KeystoreEntryConfigEntry = {
  /// The configuration entry key
  key: Buffer;
  /// The length of the configuration entry value
  valueLength: number;
  /// The configuration entry value
  value: Buffer;
};

/**
 * Returns the length of a `KeystoreEntryConfigEntry`
 * @param configEntry The `KeystoreEntryConfigEntry`
 * @returns Length of the `KeystoreEntryConfigEntry`
 */
export function keystoreEntryConfigEntryLength(
  configEntry: KeystoreEntryConfigEntry,
): number {
  return 12 + configEntry.valueLength;
}

/**
 * Packs a `KeystoreEntryConfigEntry` into a vector of bytes
 * @param configEntry A `KeystoreEntryConfigEntry`
 * @returns Buffer
 */
export function packKeystoreEntryConfigEntry(
  configEntry: KeystoreEntryConfigEntry,
): Buffer {
  const data = Buffer.alloc(12 + configEntry.valueLength);
  data.set(configEntry.key);
  data.set(toBytesFromU32(configEntry.valueLength), 8);
  data.set(configEntry.value, 12);
  return data;
}

/**
 * Unpacks a slice of data into a `KeystoreEntryConfigEntry`
 * @param data Buffer
 * @returns A `KeystoreEntryConfigEntry`
 */
export function unpackKeystoreEntryConfigEntry(
  data: Buffer,
): [KeystoreEntryConfigEntry, number] {
  // If the data isn't at least 12 bytes long, it's invalid
  if (data.length < 12) {
    throw new Error("Invalid format for config entry");
  }
  // Take the configuration entry key
  const key = data.subarray(0, 8);
  // Take the length of the configuration entry
  const valueLength = toU32FromBytes(data.slice(8, 12));
  const configEntryEnd = valueLength + 12;
  // Take the configuration entry value
  const value = data.subarray(12, configEntryEnd);
  return [
    {
      key,
      valueLength,
      value,
    },
    configEntryEnd,
  ];
}

/**
 * Unpacks a slice of data into a `KeystoreEntryConfigEntry[]`
 * @param data Buffer
 * @returns A list of `KeystoreEntryConfigEntry`
 */
export function unpackKeystoreEntryConfigEntryToList(
  data: Buffer,
): KeystoreEntryConfigEntry[] {
  // Iteratively unpack config entries until there is no data left
  const configList: KeystoreEntryConfigEntry[] = [];
  while (data.length > 0) {
    const [configEntry, configEntryEnd] = unpackKeystoreEntryConfigEntry(data);
    configList.push(configEntry);
    data = data.subarray(configEntryEnd);
  }
  return configList;
}

/**
 * Configurations section in a keystore entry
 *
 * Note: This section is identified by it's unique TLV discriminator,
 * derived from the `SplDiscriminate` macro
 */
export type KeystoreEntryConfig = {
  /// A list of `KeystoreEntryConfigEntry`
  configList: KeystoreEntryConfigEntry[];
};

/**
 * Returns the length of a `KeystoreEntryConfig`
 * @param config The `KeystoreEntryConfig`
 * @returns Length of the `KeystoreEntryConfig`
 */
export function keystoreEntryConfigLength(config: KeystoreEntryConfig): number {
  let len = 12;
  for (const configEntry of config.configList) {
    len += keystoreEntryConfigEntryLength(configEntry);
  }
  return len;
}

/**
 * Packs a `KeystoreEntryConfig` into a vector of bytes
 * @param config A `KeystoreEntryConfig`
 * @returns Buffer
 */
export function packKeystoreEntryConfig(config: KeystoreEntryConfig): Buffer {
  const data = Buffer.alloc(12);
  // If there are no config entries, return a single zero in the array
  if (config.configList.length === 0) {
    return Buffer.from([0]);
  }
  // Pack each config entry into a vector of bytes
  const configEntries = config.configList.map(packKeystoreEntryConfigEntry);
  // Concatenate the config entries
  const configData = Buffer.concat(configEntries);
  let offset = 0;
  for (const configEntry of configEntries) {
    configData.set(configEntry, offset);
    offset += configEntry.length;
  }
  // Pack the discriminator
  data.set(HAS_CONFIGURATIONS_DISCRIMINATOR);
  // Pack the length of the config data
  data.set(toBytesFromU32(configData.length));
  // Concatenate the config data
  data.set(configData, 12);
  return data;
}

/**
 * Unpacks a slice of data into a `KeystoreEntryConfig`
 * @param data Buffer
 * @returns A `KeystoreEntryConfig`
 */
export function unpackKeystoreEntryConfig(
  data: Buffer,
): KeystoreEntryConfig | undefined {
  // If the first byte is 0, there is no config data
  if (data[0] === 0) {
    return undefined;
  }
  // If the data isn't at least 12 bytes long, it's invalid
  // (discriminator, length, config)
  if (data[0] !== 0 && data.length < 12) {
    throw new Error("Invalid format for config");
  }
  // Read the length of the config
  const configEnd = data[8] + 12;
  // Ensure there are no leftover bytes
  if (configEnd !== data.length) {
    throw new Error("Invalid format for config");
  }
  // Take the config data from the slice
  const configData = data.subarray(12);
  // Unpack the config data into a vector of config entries
  const configList = unpackKeystoreEntryConfigEntryToList(configData);
  return {
    configList,
  };
}

/**
 * Key section in a keystore entry
 *
 * Note: The "key discriminator" for the key section is used as the TLV
 * discriminator and passed in when creating a new keystore entry
 */
export type KeystoreEntryKey = {
  /// The key discriminator
  discriminator: Buffer;
  /// The key length
  keyLength: number;
  /// The key data
  key: Buffer;
};

/**
 * Returns the length of a `KeystoreEntryKey`
 * @param key The `KeystoreEntryKey`
 * @returns Length of the `KeystoreEntryKey`
 */
export function keystoreEntryKeyLength(key: KeystoreEntryKey): number {
  return 12 + key.keyLength;
}

/**
 * Packs a `KeystoreEntryKey` into a vector of bytes
 * @param key A `KeystoreEntryKey`
 * @returns Buffer
 */
export function packKeystoreEntryKey(key: KeystoreEntryKey): Buffer {
  const data = Buffer.alloc(12 + key.keyLength);
  data.set(key.discriminator);
  data.set(toBytesFromU32(key.keyLength), 8);
  data.set(key.key, 12);
  return data;
}

/**
 * Unpacks a slice of data into a `KeystoreEntryKey`
 * @param data Buffer
 * @returns A `KeystoreEntryKey`
 */
export function unpackKeystoreEntryKey(
  data: Buffer,
): [KeystoreEntryKey, number] {
  // If the data isn't at least 12 bytes long, it's invalid
  // (discriminator, length, key)
  if (data.length < 12) {
    throw new Error("Invalid format for key");
  }
  // Take the key discriminator
  const discriminator = data.subarray(0, 8);
  // Take the length of the key
  const keyLength = toU32FromBytes(data.subarray(8, 12));
  const keyEnd = keyLength + 12;
  // Take the key data
  const key = data.subarray(12, keyEnd);
  return [
    {
      discriminator,
      keyLength,
      key,
    },
    keyEnd + 12,
  ];
}

/**
 * A keystore entry
 *
 * Note: Each entry is identified by it's unique TLV discriminator,
 * derived from the `SplDiscriminate` macro
 */
export type KeystoreEntry = {
  /// The key data
  key: KeystoreEntryKey;
  /// Additional configuration data
  config?: KeystoreEntryConfig;
};

/**
 * Packs a `KeystoreEntry` into a vector of bytes
 * @param entry A `KeystoreEntry`
 * @returns Buffer
 */
export function packKeystoreEntry(entry: KeystoreEntry): Buffer {
  // Check if the entry has additional configurations
  if (entry.config) {
    const keyLength = keystoreEntryKeyLength(entry.key);
    const keyEnd = 12 + keyLength;
    const entryLength = keyLength + keystoreEntryConfigLength(entry.config);
    // Initialize the data
    const data = Buffer.alloc(12 + entryLength);
    // Pack the entry discriminator
    data.set(KEYSTORE_ENTRY_DISCRIMINATOR);
    // Pack the entry length
    data.set(toBytesFromU32(entryLength), 8);
    // Pack the key
    data.set(packKeystoreEntryKey(entry.key), 12);
    // Pack the config
    data.set(packKeystoreEntryConfig(entry.config), keyEnd);
    return data;
  } else {
    const keyLength = keystoreEntryKeyLength(entry.key);
    const keyEnd = 12 + keyLength;
    const entryLength = keyLength + 1;
    // Initialize the data
    const data = Buffer.alloc(12 + entryLength);
    // Pack the entry discriminator
    data.set(KEYSTORE_ENTRY_DISCRIMINATOR);
    // Pack the entry length
    data.set(toBytesFromU32(entryLength), 8);
    // Pack the key
    data.set(packKeystoreEntryKey(entry.key), 12);
    // Pack a single zero
    data.set(NO_CONFIGURATIONS_DISCRIMINATOR, keyEnd);
    return data;
  }
}

/**
 * Unpacks a slice of data into a `KeystoreEntry`
 * @param data Buffer
 * @returns A `KeystoreEntry`
 */
export function unpackKeystoreEntry(data: Buffer): [KeystoreEntry, number] {
  // If the data isn't at least 12 bytes long, it's invalid
  // (discriminator, length, key)
  if (data.length < 12) {
    throw new Error("Invalid format for entry");
  }
  // If the first 8 bytes of the slice don't match the unique TLV discriminator
  // for a new entry, it's invalid
  if (!data.subarray(0, 8).equals(KEYSTORE_ENTRY_DISCRIMINATOR)) {
    throw new Error("Invalid format for entry");
  }
  // Read the length of the keystore entry
  const entryLength = toU32FromBytes(data.subarray(8, 12));
  const entryEnd = entryLength + 12;
  const [key, keyEnd] = unpackKeystoreEntryKey(data.subarray(12, entryEnd));
  const config = unpackKeystoreEntryConfig(data.subarray(keyEnd, entryEnd));
  return [
    {
      key,
      config,
    },
    entryEnd,
  ];
}
