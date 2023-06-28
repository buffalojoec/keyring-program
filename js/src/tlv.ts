import { Buffer } from "buffer";
import {
  HAS_CONFIGURATIONS_DISCRIMINATOR,
  KEYSTORE_ENTRY_DISCRIMINATOR,
  NO_CONFIGURATIONS_DISCRIMINATOR,
} from "./algorithm";

/**
 * Converts a number to a Uint8Array for a u32
 * @param num A u32 number
 * @returns Uint8Array
 */
function toBytesFromU32(num: number): Uint8Array {
  let data = Buffer.alloc(4);
  data.writeUInt32LE(num, 0);
  return data;
}

/**
 * Converts a Uint8Array to a number for a u32
 * @param bytes The bytes to convert
 * @returns Number for the u32
 */
function toU32FromBytes(bytes: Uint8Array): number {
  return Buffer.from(bytes.buffer).readUInt32LE(0);
}

/**
 * Configurations section in a keystore entry
 *
 * Note: This section is identified by it's unique TLV discriminator,
 * derived from the `SplDiscriminate` macro
 */
export type KeystoreEntryConfigEntry = {
  /// The configuration entry key
  key: Uint8Array;
  /// The length of the configuration entry value
  valueLength: number;
  /// The configuration entry value
  value: Uint8Array;
};

/**
 * Returns the length of a `KeystoreEntryConfigEntry`
 * @param configEntry The `KeystoreEntryConfigEntry`
 * @returns Length of the `KeystoreEntryConfigEntry`
 */
export function keystoreEntryConfigEntryLength(
  configEntry: KeystoreEntryConfigEntry
): number {
  return 12 + configEntry.valueLength;
}

/**
 * Packs a `KeystoreEntryConfigEntry` into a vector of bytes
 * @param configEntry A `KeystoreEntryConfigEntry`
 * @returns Uint8Array
 */
export function packKeystoreEntryConfigEntry(
  configEntry: KeystoreEntryConfigEntry
): Uint8Array {
  const data = new Uint8Array(12 + configEntry.valueLength);
  data.set(configEntry.key);
  data.set(toBytesFromU32(configEntry.valueLength), 8);
  data.set(configEntry.value, 12);
  return data;
}

/**
 * Unpacks a slice of data into a `KeystoreEntryConfigEntry`
 * @param data Uint8Array
 * @returns A `KeystoreEntryConfigEntry`
 */
export function unpackKeystoreEntryConfigEntry(
  data: Uint8Array
): [KeystoreEntryConfigEntry, number] {
  // If the data isn't at least 12 bytes long, it's invalid
  if (data.length < 12) {
    throw new Error("Invalid format for config entry");
  }
  // Take the configuration entry key
  const key = data.slice(0, 8);
  // Take the length of the configuration entry
  const valueLength = toU32FromBytes(data.slice(8, 12));
  const configEntryEnd = valueLength + 12;
  // Take the configuration entry value
  const value = data.slice(12, configEntryEnd);
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
 * @param data Uint8Array
 * @returns A list of `KeystoreEntryConfigEntry`
 */
export function unpackKeystoreEntryConfigEntryToList(
  data: Uint8Array
): KeystoreEntryConfigEntry[] {
  // Iteratively unpack config entries until there is no data left
  const configList: KeystoreEntryConfigEntry[] = [];
  while (data.length > 0) {
    const [configEntry, configEntryEnd] = unpackKeystoreEntryConfigEntry(data);
    configList.push(configEntry);
    data = data.slice(configEntryEnd);
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
 * @returns Uint8Array
 */
export function packKeystoreEntryConfig(
  config: KeystoreEntryConfig
): Uint8Array {
  const data = new Uint8Array(12);
  // If there are no config entries, return a single zero in the array
  if (config.configList.length === 0) {
    return new Uint8Array([0]);
  }
  // Pack each config entry into a vector of bytes
  const configEntries = config.configList.map(packKeystoreEntryConfigEntry);
  // Concatenate the config entries
  const configData = new Uint8Array(
    configEntries.reduce((a, b) => a + b.length, 0)
  );
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
 * @param data Uint8Array
 * @returns A `KeystoreEntryConfig`
 */
export function unpackKeystoreEntryConfig(
  data: Uint8Array
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
  const configData = data.slice(12);
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
  discriminator: Uint8Array;
  /// The key length
  keyLength: number;
  /// The key data
  key: Uint8Array;
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
 * @returns Uint8Array
 */
export function packKeystoreEntryKey(key: KeystoreEntryKey): Uint8Array {
  const data = new Uint8Array(12 + key.keyLength);
  data.set(key.discriminator);
  data.set(toBytesFromU32(key.keyLength), 8);
  data.set(key.key, 12);
  return data;
}

/**
 * Unpacks a slice of data into a `KeystoreEntryKey`
 * @param data Uint8Array
 * @returns A `KeystoreEntryKey`
 */
export function unpackKeystoreEntryKey(
  data: Uint8Array
): [KeystoreEntryKey, number] {
  // If the data isn't at least 12 bytes long, it's invalid
  // (discriminator, length, key)
  if (data.length < 12) {
    throw new Error("Invalid format for key");
  }
  // Take the key discriminator
  const discriminator = data.slice(0, 8);
  // Take the length of the key
  const keyLength = toU32FromBytes(data.slice(8, 12));
  const keyEnd = keyLength + 12;
  // Take the key data
  const key = data.slice(12, keyEnd);
  return [
    {
      discriminator,
      keyLength,
      key,
    },
    keyEnd,
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
 * @returns Uint8Array
 */
export function packKeystoreEntry(entry: KeystoreEntry): Uint8Array {
  // Initialize the data
  const data = new Uint8Array(12);
  // Pack the entry discriminator
  data.set(KEYSTORE_ENTRY_DISCRIMINATOR);
  // Get the length of the key and its end index
  let keyLength = keystoreEntryKeyLength(entry.key);
  let keyEnd = 12 + keyLength;
  // Check if the entry has additional configurations
  if (entry.config) {
    // Pack the entry length
    const entryLength =
      keystoreEntryKeyLength(entry.key) +
      keystoreEntryConfigLength(entry.config);
    data.set(toBytesFromU32(entryLength), 8);
    // Pack the key
    data.set(packKeystoreEntryKey(entry.key), 12);
    // Pack the config
    data.set(packKeystoreEntryConfig(entry.config), keyEnd);
  } else {
    // Pack the entry length
    const entryLength = keystoreEntryKeyLength(entry.key) + 1;
    data.set(toBytesFromU32(entryLength), 8);
    // Pack the key
    data.set(packKeystoreEntryKey(entry.key), 12);
    // Pack a single zero
    data.set(NO_CONFIGURATIONS_DISCRIMINATOR, keyEnd);
  }
  return data;
}

/**
 * Unpacks a slice of data into a `KeystoreEntry`
 * @param data Uint8Array
 * @returns A `KeystoreEntry`
 */
export function unpackKeystoreEntry(data: Uint8Array): [KeystoreEntry, number] {
  // If the data isn't at least 12 bytes long, it's invalid
  // (discriminator, length, key)
  if (data.length < 12) {
    throw new Error("Invalid format for entry");
  }
  // If the first 8 bytes of the slice don't match the unique TLV discriminator
  // for a new entry, it's invalid
  if (
    !data.slice(0, 8).every((v, i) => v === KEYSTORE_ENTRY_DISCRIMINATOR[i])
  ) {
    throw new Error("Invalid format for entry");
  }
  // Read the length of the keystore entry
  const entryLength = toU32FromBytes(data.slice(8, 12));
  const entryEnd = entryLength + 12;
  const [key, keyEnd] = unpackKeystoreEntryKey(data.slice(12, entryEnd));
  const config = unpackKeystoreEntryConfig(data.slice(keyEnd, entryEnd));
  return [
    {
      key,
      config,
    },
    entryEnd,
  ];
}
