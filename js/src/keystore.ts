import { deserialize as borshDeserialize } from "borsh";

/**
 * A keystore
 */
export class Keystore {
  entries: EncryptionKeyConfig[];
  constructor(entries: EncryptionKeyConfig[]) {
    this.entries = entries;
  }

  /**
   * Get the packed length of the entire keystore
   * @returns The packed length of the entire keystore
   */
  packedLength(): number {
    return this.entries.reduce(
      (sum, entry) => sum + entry.getPackedLength(),
      0,
    );
  }

  /**
   * Serialize the keystore
   * @returns A buffer containing the serialized keystore
   */
  serialize(): Buffer {
    const buf = Buffer.alloc(this.packedLength() + 4);
    buf.writeUInt32LE(this.entries.length, 0);
    let offset = 4;
    for (const entry of this.entries) {
      const entryBuf = entry.serialize();
      entryBuf.copy(buf, offset);
      offset += entryBuf.length;
    }
    return buf;
  }

  /**
   * Deserialize a keystore from a buffer
   * @param buf A buffer
   * @returns The deserialized keystore
   */
  static deserialize(buf: Buffer): Keystore {
    if (buf.length === 0) {
      return new Keystore([]);
    }
    const entryCount = buf.subarray(0, 4).readUInt32LE(0);
    let data = buf.subarray(4);
    const entries = [];
    for (let i = 0; i < entryCount; i++) {
      const type = data[0];
      const packedLength = getEntryPackedLength(type);
      const entry = deserializeEntry(type, data.subarray(1, packedLength));
      data = data.subarray(packedLength);
      entries.push(entry);
    }
    return new Keystore(entries);
  }
}

/**
 * An enum for defining recognized encryption algorithms
 */
enum EncryptionKeyConfigType {
  // Curve25519 encryption algorithm
  Curve25519 = 0,
  // RSA encryption algorithm
  Rsa = 1,
  // ComplexAlgorithm encryption algorithm (example)
  ComplexAlgorithm = 2,
}

/**
 * An interface for defining recognized encryption algorithms
 */
export interface EncryptionKeyConfig {
  // The type of encryption algorithm
  readonly type: EncryptionKeyConfigType;
  // The packed length of the entire key config
  getPackedLength(): number;
  // Serialize the key config
  serialize(): Buffer;
}

/**
 * Curve25519 encryption algorithm
 */
export class Curve25519 implements EncryptionKeyConfig {
  static KEY_LENGTH = 32;
  static PACKED_LENGTH = 1 + Curve25519.KEY_LENGTH;

  readonly type: EncryptionKeyConfigType = EncryptionKeyConfigType.Curve25519;

  key: Buffer;
  constructor(key: Buffer) {
    if (key.length !== Curve25519.KEY_LENGTH) {
      throw new Error(`Invalid key length for Curve25519: ${key.length}`);
    }
    this.key = key;
  }
  getPackedLength(): number {
    return Curve25519.PACKED_LENGTH;
  }
  serialize(): Buffer {
    const buf = Buffer.alloc(this.getPackedLength());
    buf[0] = this.type;
    buf.set(this.key, 1);
    return buf;
  }
  static deserialize(buf: Buffer): Curve25519 {
    return new Curve25519(buf);
  }
}

/**
 * RSA encryption algorithm
 */
export class Rsa implements EncryptionKeyConfig {
  static KEY_LENGTH = 64;
  static PACKED_LENGTH = 1 + Rsa.KEY_LENGTH;

  readonly type: EncryptionKeyConfigType = EncryptionKeyConfigType.Rsa;

  key: Buffer;
  constructor(key: Buffer) {
    if (key.length !== Rsa.KEY_LENGTH) {
      throw new Error(`Invalid key length for RSA: ${key.length}`);
    }
    this.key = key;
  }
  getPackedLength(): number {
    return Rsa.PACKED_LENGTH;
  }
  serialize(): Buffer {
    const buf = Buffer.alloc(this.getPackedLength());
    buf[0] = this.type;
    buf.set(this.key, 1);
    return buf;
  }
  static deserialize(buf: Buffer): Rsa {
    return new Rsa(buf);
  }
}

/**
 * ComplexAlgorithm encryption algorithm (example)
 */
export class ComplexAlgorithm implements EncryptionKeyConfig {
  static KEY_LENGTH = 32;
  static PACKED_LENGTH = 1 + ComplexAlgorithm.KEY_LENGTH;

  readonly type: EncryptionKeyConfigType =
    EncryptionKeyConfigType.ComplexAlgorithm;

  key: Buffer;
  constructor(key: Buffer) {
    if (key.length !== ComplexAlgorithm.KEY_LENGTH) {
      throw new Error(`Invalid key length for ComplexAlgorithm: ${key.length}`);
    }
    this.key = key;
  }
  getPackedLength(): number {
    return ComplexAlgorithm.PACKED_LENGTH;
  }
  serialize(): Buffer {
    const buf = Buffer.alloc(this.getPackedLength());
    buf[0] = this.type;
    buf.set(this.key, 1);
    return buf;
  }
  static deserialize(buf: Buffer): ComplexAlgorithm {
    return new ComplexAlgorithm(buf);
  }
}

/**
 * Deserialize an encryption key config from a buffer
 * @param type The type of encryption key config
 * @param buf The buffer
 * @returns The deserialized encryption key config
 */
function getEntryPackedLength(type: EncryptionKeyConfigType): number {
  switch (type) {
    case EncryptionKeyConfigType.Curve25519:
      return Curve25519.PACKED_LENGTH;
    case EncryptionKeyConfigType.Rsa:
      return Rsa.PACKED_LENGTH;
    case EncryptionKeyConfigType.ComplexAlgorithm:
      return ComplexAlgorithm.PACKED_LENGTH;
    default:
      throw new Error(`Unknown encryption key config type: ${type}`);
  }
}

/**
 * Deserialize an encryption key config from a buffer
 * @param type The type of encryption key config
 * @param buf The buffer
 * @returns The deserialized encryption key config
 */
function deserializeEntry(
  type: EncryptionKeyConfigType,
  buf: Buffer,
): EncryptionKeyConfig {
  switch (type) {
    case EncryptionKeyConfigType.Curve25519:
      return Curve25519.deserialize(buf);
    case EncryptionKeyConfigType.Rsa:
      return Rsa.deserialize(buf);
    case EncryptionKeyConfigType.ComplexAlgorithm:
      return ComplexAlgorithm.deserialize(buf);
    default:
      throw new Error(`Unknown encryption key config type: ${type}`);
  }
}
