//! State representations of recognized encryption algorithms

use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_sdk::program_error::ProgramError,
    spl_discriminator::{ArrayDiscriminator, SplDiscriminate},
    spl_keyring_program::tlv::{
        KeystoreEntry, KeystoreEntryConfig, KeystoreEntryConfigEntry, KeystoreEntryKey,
    },
};

/// A trait for defining recognized encryption algorithms
pub trait EncryptionAlgorithm: BorshDeserialize + BorshSerialize + SplDiscriminate {
    /// Returns the key
    fn key(&self) -> Vec<u8>;
    /// Returns the config as an `Option<KeystoreEntryConfig>`
    fn keystore_entry_config(&self) -> Option<KeystoreEntryConfig>;
    /// Converts an encryption algorithm to a buffer
    fn to_buffer(&self) -> Result<Vec<u8>, ProgramError> {
        let mut buffer = Vec::new();
        self.serialize(&mut buffer)?;
        Ok(buffer)
    }
    /// Converts an encryption algorithm to a keystore entry
    fn to_keystore_entry(&self) -> Result<KeystoreEntry, ProgramError> {
        KeystoreEntry::new(
            KeystoreEntryKey {
                discriminator: Self::SPL_DISCRIMINATOR,
                key: self.key(),
            },
            self.keystore_entry_config(),
        )
    }
}

/// A trait representing the configurations of an encryption algorithm
pub trait Configurations: BorshDeserialize + BorshSerialize {
    /// Converts configurations to a buffer
    fn to_buffer(&self) -> Result<Vec<u8>, ProgramError>;
    /// Converts configurations to a `KeystoreEntryConfig`
    fn to_keystore_entry_config(&self) -> Option<KeystoreEntryConfig>;
}

/// Struct representing "no configurations" required for a particular encryption
/// algorithm
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct NoConfigurations;

impl Configurations for NoConfigurations {
    fn to_buffer(&self) -> Result<Vec<u8>, ProgramError> {
        Ok(vec![0])
    }
    fn to_keystore_entry_config(&self) -> Option<KeystoreEntryConfig> {
        None
    }
}

/// Curve25519 encryption algorithm
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:key:Curve25519")]
pub struct Curve25519([u8; 32]);
impl Curve25519 {
    /// Create a new instance of Curve25519
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
}

impl EncryptionAlgorithm for Curve25519 {
    fn key(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn keystore_entry_config(&self) -> Option<KeystoreEntryConfig> {
        NoConfigurations::default().to_keystore_entry_config()
    }
}

/// Rsa encryption algorithm
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:key:RSA")]
pub struct Rsa([u8; 64]);
impl Rsa {
    /// Create a new instance of Rsa
    pub fn new(key: [u8; 64]) -> Self {
        Self(key)
    }
}

impl EncryptionAlgorithm for Rsa {
    fn key(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn keystore_entry_config(&self) -> Option<KeystoreEntryConfig> {
        NoConfigurations::default().to_keystore_entry_config()
    }
}

/// ComplexAlgorithm encryption algorithm
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:key:ComplexAlgorithm")]
pub struct ComplexAlgorithm {
    key: [u8; 32],
    config: ComplexAlgorithmConfigurations,
}
impl ComplexAlgorithm {
    /// Create a new instance of ComplexAlgorithm
    pub fn new(key: [u8; 32], nonce: [u8; 12], aad: [u8; 12]) -> Self {
        Self {
            key,
            config: ComplexAlgorithmConfigurations { nonce, aad },
        }
    }
}

impl EncryptionAlgorithm for ComplexAlgorithm {
    fn key(&self) -> Vec<u8> {
        self.key.to_vec()
    }

    fn keystore_entry_config(&self) -> Option<KeystoreEntryConfig> {
        self.config.to_keystore_entry_config()
    }
}

/// ComplexAlgorithm configurations
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:configuration:ComplexAlgorithm")]
pub struct ComplexAlgorithmConfigurations {
    /// The nonce used for encryption
    pub nonce: [u8; Self::NONCE_LENGTH],
    /// The additional authenticated data
    pub aad: [u8; Self::AAD_LENGTH],
}

impl ComplexAlgorithmConfigurations {
    /// The length of the nonce in bytes
    const NONCE_LENGTH: usize = 12;
    /// The length of the additional authenticated data in bytes
    const AAD_LENGTH: usize = 12;
}

impl Configurations for ComplexAlgorithmConfigurations {
    fn to_buffer(&self) -> Result<Vec<u8>, ProgramError> {
        let mut buffer = Vec::new();
        self.serialize(&mut buffer)?;
        Ok(buffer)
    }

    fn to_keystore_entry_config(&self) -> Option<KeystoreEntryConfig> {
        // 8 Bytes
        let nonce_discriminator = {
            let mut buffer = [0; 8];
            b"nonce".iter().enumerate().for_each(|(i, byte)| {
                buffer[i] = *byte;
            });
            ArrayDiscriminator::new(buffer)
        };
        // 8 Bytes
        let aad_discriminator = {
            let mut buffer = [0; 8];
            b"aad".iter().enumerate().for_each(|(i, byte)| {
                buffer[i] = *byte;
            });
            ArrayDiscriminator::new(buffer)
        };
        Some(KeystoreEntryConfig(vec![
            KeystoreEntryConfigEntry {
                key: nonce_discriminator,
                value: self.nonce.to_vec(),
            },
            KeystoreEntryConfigEntry {
                key: aad_discriminator,
                value: self.aad.to_vec(),
            },
        ]))
    }
}
