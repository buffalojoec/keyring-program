import { Buffer } from "buffer";
import { KeystoreEntry, KeystoreEntryConfig } from "./tlv";

// First 8 bytes of the string literal: "spl_keyring_program:keystore_entry"
export const KEYSTORE_ENTRY_DISCRIMINATOR: Buffer = Buffer.from([
  22, 52, 242, 31, 193, 53, 26, 243,
]);
// First 8 bytes of the string literal: "spl_keyring_program:keystore_entry:configuration"
export const HAS_CONFIGURATIONS_DISCRIMINATOR: Buffer = Buffer.from([
  152, 237, 14, 242, 40, 241, 192, 210,
]);

/**
 * An interface for defining recognized encryption algorithms
 */
export interface EncryptionAlgorithm {
  keyDiscriminator: Buffer;
  keyLength: number;
  key: Buffer;
  config: Configurations;
  toBuffer(): Buffer;
  toKeystoreEntry(): KeystoreEntry;
}

/**
 * Converts an encryption algorithm to a buffer
 * @param algorithm An encryption algorithm
 * @returns A buffer
 */
export function fromEncryptionAlgorithmToBuffer(
  algorithm: EncryptionAlgorithm,
): Buffer {
  return Buffer.concat([
    Buffer.from(algorithm.keyDiscriminator),
    Buffer.from(Uint32Array.of(algorithm.keyLength)),
    Buffer.from(algorithm.key),
    algorithm.config.toBuffer(),
  ]);
}

/**
 * Converts an encryption algorithm to a keystore entry
 * @param algorithm An encryption algorithm
 * @returns A keystore entry
 */
export function fromEncryptionAlgorithmToKeystoreEntry(
  algorithm: EncryptionAlgorithm,
): KeystoreEntry {
  return {
    key: {
      discriminator: algorithm.keyDiscriminator,
      keyLength: algorithm.keyLength,
      key: algorithm.key,
    },
    config: algorithm.config.toKeystoreEntryConfig(),
  };
}

/**
 * Interface representing the configurations of an encryption algorithm
 */
export interface Configurations {
  configurationDiscriminator: Buffer;
  toBuffer(): Buffer;
  toKeystoreEntryConfig(): KeystoreEntryConfig | undefined;
}

/**
 * Class representing "no configurations" required for a
 * particular encryption algorithm
 */
class NoConfigurations implements Configurations {
  configurationDiscriminator: Buffer = NO_CONFIGURATIONS_DISCRIMINATOR;
  constructor() {}
  toBuffer(): Buffer {
    return Buffer.from(this.configurationDiscriminator);
  }
  toKeystoreEntryConfig(): KeystoreEntryConfig | undefined {
    return undefined;
  }
}
// Single zero
export const NO_CONFIGURATIONS_DISCRIMINATOR: Buffer = Buffer.from([0]);

/**
 * Curve25519 encryption algorithm
 */
export class Curve25519 implements EncryptionAlgorithm {
  keyDiscriminator: Buffer = CURVE25519_DISCRIMINATOR;
  keyLength: number = 32;
  key: Buffer;
  config: Configurations = new NoConfigurations();
  constructor(key: Buffer) {
    this.key = key;
  }
  toBuffer(): Buffer {
    return fromEncryptionAlgorithmToBuffer(this);
  }
  toKeystoreEntry(): KeystoreEntry {
    return fromEncryptionAlgorithmToKeystoreEntry(this);
  }
}
// First 8 bytes of the string literal: "spl_keyring_program:key:Curve25519"
export const CURVE25519_DISCRIMINATOR: Buffer = Buffer.from([
  91, 118, 136, 53, 132, 35, 78, 142,
]);

/**
 * RSA encryption algorithm
 */
export class RSA implements EncryptionAlgorithm {
  keyDiscriminator: Buffer = RSA_DISCRIMINATOR;
  keyLength: number = 32;
  key: Buffer;
  config: Configurations = new NoConfigurations();
  constructor(key: Buffer) {
    this.key = key;
  }
  toBuffer(): Buffer {
    return fromEncryptionAlgorithmToBuffer(this);
  }
  toKeystoreEntry(): KeystoreEntry {
    return fromEncryptionAlgorithmToKeystoreEntry(this);
  }
}
// First 8 bytes of the string literal: "spl_keyring_program:key:RSA"
export const RSA_DISCRIMINATOR: Buffer = Buffer.from([
  201, 12, 106, 206, 86, 201, 19, 89,
]);

/**
 * ComplexAlgorithm encryption algorithm
 */
export class ComplexAlgorithm implements EncryptionAlgorithm {
  keyDiscriminator: Buffer = COMPLEX_ALGORITHM_DISCRIMINATOR;
  keyLength: number = 32;
  key: Buffer;
  config: Configurations;
  constructor(key: Buffer, config: ComplexAlgorithmConfigurations) {
    this.key = key;
    this.config = config;
  }
  toBuffer(): Buffer {
    return fromEncryptionAlgorithmToBuffer(this);
  }
  toKeystoreEntry(): KeystoreEntry {
    return fromEncryptionAlgorithmToKeystoreEntry(this);
  }
}
// First 8 bytes of the string literal: "spl_keyring_program:key:ComplexAlgorithm"
export const COMPLEX_ALGORITHM_DISCRIMINATOR: Buffer = Buffer.from([
  238, 108, 0, 133, 126, 20, 221, 160,
]);

/**
 * ComplexAlgorithm configurations
 */
export class ComplexAlgorithmConfigurations implements Configurations {
  configurationDiscriminator: Buffer =
    COMPLEX_ALGORITHM_CONFIGURATION_DISCRIMINATOR;
  // The nonce used for encryption
  nonce: Buffer;
  // The additional authenticated data
  aad: Buffer;
  constructor(nonce: Buffer, aad: Buffer) {
    this.nonce = nonce;
    this.aad = aad;
  }
  toBuffer(): Buffer {
    return Buffer.concat([
      Buffer.from(this.configurationDiscriminator),
      Buffer.from(this.nonce),
      Buffer.from(this.aad),
    ]);
  }
  toKeystoreEntryConfig(): KeystoreEntryConfig {
    return {
      configList: [
        {
          key: Buffer.from("nonce"),
          valueLength: this.nonce.length,
          value: Buffer.from(this.nonce),
        },
        {
          key: Buffer.from("aad"),
          valueLength: this.aad.length,
          value: Buffer.from(this.aad),
        },
      ],
    };
  }
}
// First 8 bytes of the string literal: "spl_keyring_program:configuration:ComplexAlgorithm"
export const COMPLEX_ALGORITHM_CONFIGURATION_DISCRIMINATOR = Buffer.from([
  62, 5, 140, 55, 241, 136, 249, 202,
]);

/**
 * Reads a keystore entry and converts it to one of the above recognized encryption algorithms
 * @param keystoreEntry A keystore entry
 * @returns An encryption algorithm
 */
export function fromKeystoreEntrytoEncryptionAlgorithm(
  keystoreEntry: KeystoreEntry,
): EncryptionAlgorithm {
  const keyDiscriminator = keystoreEntry.key.discriminator;
  const key = keystoreEntry.key.key;
  if (keyDiscriminator.equals(CURVE25519_DISCRIMINATOR)) {
    return new Curve25519(key);
  } else if (keyDiscriminator.equals(RSA_DISCRIMINATOR)) {
    return new RSA(key);
  } else if (keyDiscriminator.equals(COMPLEX_ALGORITHM_DISCRIMINATOR)) {
    const config = keystoreEntry.config;
    if (!config) {
      throw new Error("Missing required config for ComplexAlgorithm");
    }
    const configList = config.configList;
    const nonce = configList[0].value;
    const aad = configList[1].value;
    return new ComplexAlgorithm(
      key,
      new ComplexAlgorithmConfigurations(nonce, aad),
    );
  } else {
    throw new Error("Unrecognized key discriminator");
  }
}
