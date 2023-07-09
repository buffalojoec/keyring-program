//! Types for managing the nested TLV structure of the keystore entry data

use {
    crate::error::KeyringProgramError,
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::program_error::ProgramError,
    spl_discriminator::{ArrayDiscriminator, SplDiscriminate},
};

/// Length of the 8-byte TLV discriminator plus a `u32` length value
const DISCRIM_PLUS_LENGTH: usize = 12;

/// Key-value entry for additional encryption algorithm configurations
///
/// Note: The "key" for this key-value entry is used as the TLV discriminator
/// and passed in when creating a new configuration entry
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct KeystoreEntryConfigEntry {
    /// The configuration entry key
    pub key: ArrayDiscriminator,
    /// The configuration entry value
    pub value: Vec<u8>,
}
impl KeystoreEntryConfigEntry {
    /// Returns the length of a `KeystoreEntryConfigEntry`
    pub fn data_len(&self) -> usize {
        DISCRIM_PLUS_LENGTH + self.value.len()
    }

    /// Packs a `KeystoreEntryConfigEntry` into a vector of bytes
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        let mut data = Vec::new();
        self.serialize(&mut data)?;
        Ok(data)
    }

    /// Unpacks a slice of data into a `KeystoreEntryConfigEntry`
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        Self::try_from_slice(data)
            .map_err(|_| KeyringProgramError::InvalidFormatForConfigEntry.into())
    }

    /// Unpacks a slice of data into a `Vec<KeystoreEntryConfigEntry>`
    pub fn unpack_to_vec(data: &[u8]) -> Result<Vec<Self>, ProgramError> {
        BorshDeserialize::try_from_slice(data)
            .map_err(|_| KeyringProgramError::InvalidFormatForConfigEntry.into())
    }
}

/// Configurations section in a keystore entry
///
/// Note: This section is identified by it's unique TLV discriminator,
/// derived from the `SplDiscriminate` macro
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:keystore_entry:configuration")]
pub struct KeystoreEntryConfig(pub Vec<KeystoreEntryConfigEntry>);
impl KeystoreEntryConfig {
    /// Returns the length of a `KeystoreEntryConfig`
    pub fn data_len(&self) -> usize {
        let mut len = DISCRIM_PLUS_LENGTH;
        for config_entry in &self.0 {
            len += config_entry.data_len();
        }
        len
    }

    /// Packs a `KeystoreEntryConfig` into a vector of bytes
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        let mut data = Vec::new();
        for config_entry in &self.0 {
            data.extend_from_slice(&config_entry.pack()?);
        }
        Ok(data)
    }

    /// Unpacks a slice of data into a `KeystoreEntryConfig`
    pub fn unpack(data: &[u8]) -> Result<Option<Self>, ProgramError> {
        // If the first byte is 0, there is no config data
        if data[0] == 0 && data.len() == 1 {
            return Ok(None);
        } else {
            match Self::try_from_slice(data) {
                Ok(config) => Ok(Some(config)),
                Err(_) => Err(KeyringProgramError::InvalidFormatForConfig.into()),
            }
        }
    }
}

/// Key section in a keystore entry
///
/// Note: The "key discriminator" for the key section is used as the TLV
/// discriminator and passed in when creating a new keystore entry
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct KeystoreEntryKey {
    /// The key discriminator
    pub discriminator: ArrayDiscriminator,
    /// The key data
    pub key: Vec<u8>,
}
impl KeystoreEntryKey {
    /// Returns the length of a `KeystoreEntryKey`
    pub fn data_len(&self) -> usize {
        DISCRIM_PLUS_LENGTH + self.key.len()
    }

    /// Packs a `KeystoreEntryKey` into a vector of bytes
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        let mut data = Vec::new();
        self.serialize(&mut data)?;
        Ok(data)
    }

    /// Unpacks a slice of data into a `KeystoreEntryKey`
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        Self::try_from_slice(data).map_err(|_| KeyringProgramError::InvalidFormatForKey.into())
    }
}

/// A keystore entry
///
/// Note: Each entry is identified by it's unique TLV discriminator,
/// derived from the `SplDiscriminate` macro
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:keystore_entry")]
pub struct KeystoreEntry {
    /// The new entry discriminator
    pub discriminator: ArrayDiscriminator,
    /// The key data
    pub key: KeystoreEntryKey,
    /// Additional configuration data
    pub config: Option<KeystoreEntryConfig>,
}
impl KeystoreEntry {
    /// Creates a new `KeystoreEntry`
    pub fn new(
        key: KeystoreEntryKey,
        config: Option<KeystoreEntryConfig>,
    ) -> Result<Self, ProgramError> {
        Ok(Self {
            discriminator: Self::SPL_DISCRIMINATOR,
            key,
            config,
        })
    }

    /// Returns the length of the keystore entry
    pub fn data_len(&self) -> usize {
        let mut len = DISCRIM_PLUS_LENGTH + self.key.data_len();
        if let Some(config) = &self.config {
            len += config.data_len();
        }
        len
    }

    /// Packs a `KeystoreEntry` into a vector of bytes
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        let mut data = Vec::new();
        self.serialize(&mut data)?;
        Ok(data)
    }

    /// Unpacks a slice of data into a `KeystoreEntry`
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        Self::try_from_slice(data).map_err(|_| KeyringProgramError::InvalidFormatForEntry.into())
    }
}
