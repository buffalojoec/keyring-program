//! Types for managing the nested TLV structure of the keystore entry data

use {
    crate::error::KeyringProgramError,
    solana_program::program_error::ProgramError,
    spl_discriminator::{ArrayDiscriminator, SplDiscriminate},
};

/// Key-value entry for additional encryption algorithm configurations
///
/// Note: The "key" for this key-value entry is used as the TLV discriminator
/// and passed in when creating a new configuration entry
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeystoreEntryConfigEntry {
    /// The configuration entry key
    pub key: ArrayDiscriminator,
    /// The length of the configuration entry value
    pub value_length: u32,
    /// The configuration entry value
    pub value: Vec<u8>,
}
impl KeystoreEntryConfigEntry {
    /// Returns the length of a `KeystoreEntryConfigEntry`
    pub fn data_len(&self) -> usize {
        12 + self.value_length as usize
    }

    /// Packs a `KeystoreEntryConfigEntry` into a vector of bytes
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        let mut data = Vec::new();
        data.extend_from_slice(self.key.as_slice());
        data.extend_from_slice(&self.value_length.to_le_bytes());
        data.extend_from_slice(&self.value);
        Ok(data)
    }

    /// Unpacks a slice of data into a `KeystoreEntryConfigEntry`
    pub fn unpack(data: &[u8]) -> Result<(Self, usize), ProgramError> {
        // If the data isn't at least 12 bytes long, it's invalid
        if data.len() < 12 {
            return Err(KeyringProgramError::InvalidFormatForConfigEntry.into());
        }
        // Take the configuration entry key
        let key = data[0..8].try_into().unwrap();
        // Take the length of the configuration entry
        let value_length = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let config_entry_end = value_length as usize + 12;
        // Take the configuration entry value
        let value = data[12..config_entry_end].to_vec();
        Ok((
            Self {
                key,
                value_length,
                value,
            },
            config_entry_end,
        ))
    }

    /// Unpacks a slice of data into a `Vec<KeystoreEntryConfigEntry>`
    pub fn unpack_to_vec(data: &[u8]) -> Result<Vec<Self>, ProgramError> {
        // Iteratively unpack config entries until there is no data left
        let mut config_vec = Vec::new();
        let mut data = data;
        while !data.is_empty() {
            let (config_entry, config_entry_end) = Self::unpack(data)?;
            config_vec.push(config_entry);
            data = &data[config_entry_end..];
        }
        Ok(config_vec)
    }
}

/// Configurations section in a keystore entry
///
/// Note: This section is identified by it's unique TLV discriminator,
/// derived from the `SplDiscriminate` macro
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:keystore_entry:configuration")]
pub struct KeystoreEntryConfig(Vec<KeystoreEntryConfigEntry>);
impl KeystoreEntryConfig {
    /// Returns the length of a `KeystoreEntryConfig`
    pub fn data_len(&self) -> usize {
        let mut len = 12;
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
        if data[0] == 0 {
            return Ok(None);
        }
        // If the data isn't at least 12 bytes long, it's invalid
        // (discriminator, length, config)
        if data[0] != 0 && data.len() < 12 {
            return Err(KeyringProgramError::InvalidFormatForConfig.into());
        }
        if &data[0..8] != Self::SPL_DISCRIMINATOR_SLICE {
            return Err(KeyringProgramError::InvalidFormatForConfig.into());
        }
        // Read the length of the config
        let config_end = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize + 12;
        // Ensure there are no leftover bytes
        if config_end != data.len() {
            return Err(KeyringProgramError::InvalidFormatForConfig.into());
        }
        // Take the config data from the slice
        let config_data = &data[12..];
        // Unpack the config data into a vector of config entries
        let config_vec = KeystoreEntryConfigEntry::unpack_to_vec(config_data)?;
        Ok(Some(Self(config_vec)))
    }
}

/// Key section in a keystore entry
///
/// Note: The "key discriminator" for the key section is used as the TLV
/// discriminator and passed in when creating a new keystore entry
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeystoreEntryKey {
    /// The key discriminator
    pub discriminator: ArrayDiscriminator,
    /// The key length
    pub key_length: u32,
    /// The key data
    pub key: Vec<u8>,
}
impl KeystoreEntryKey {
    /// Returns the length of a `KeystoreEntryKey`
    pub fn data_len(&self) -> usize {
        12 + self.key.len()
    }

    /// Packs a `KeystoreEntryKey` into a vector of bytes
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        let mut data = Vec::new();
        data.extend_from_slice(self.discriminator.as_slice());
        data.extend_from_slice(&self.key_length.to_le_bytes());
        data.extend_from_slice(&self.key);
        Ok(data)
    }

    /// Unpacks a slice of data into a `KeystoreEntryKey`
    pub fn unpack(data: &[u8]) -> Result<(Self, usize), ProgramError> {
        // If the data isn't at least 12 bytes long, it's invalid
        // (discriminator, length, key)
        if data.len() < 12 {
            return Err(KeyringProgramError::InvalidFormatForKey.into());
        }
        // Take the key discriminator
        let discriminator = data[0..8].try_into().unwrap();
        // Take the length of the key
        let key_length = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let key_end = key_length as usize + 12;
        // Take the key data
        let key = data[12..key_end].to_vec();
        Ok((
            Self {
                discriminator,
                key_length,
                key,
            },
            key_end,
        ))
    }
}

/// A keystore entry
///
/// Note: Each entry is identified by it's unique TLV discriminator,
/// derived from the `SplDiscriminate` macro
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:keystore_entry")]
pub struct KeystoreEntry {
    /// The key data
    pub key: KeystoreEntryKey,
    /// Additional configuration data
    pub config: Option<KeystoreEntryConfig>,
}
impl KeystoreEntry {
    /// Packs a `KeystoreEntry` into a vector of bytes
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        let mut data = Vec::new();
        // Pack the entry discriminator
        data.extend_from_slice(Self::SPL_DISCRIMINATOR_SLICE);
        // Get the length of the key and its end index
        let key_length = self.key.key_length;
        let key_end: usize = 12 + key_length as usize;
        // Check if the entry has additional configurations
        match &self.config {
            Some(config) => {
                // Pack the entry length
                let entry_length = key_end + config.data_len();
                data.extend_from_slice(&(entry_length as u32).to_le_bytes());
                // Pack the key
                data.extend_from_slice(&self.key.pack()?);
                // Pack the config
                data.extend_from_slice(&config.pack()?);
            }
            None => {
                // Pack the entry length
                let entry_length = key_end + 1;
                data.extend_from_slice(&(entry_length as u32).to_le_bytes());
                // Pack the key
                data.extend_from_slice(&self.key.pack()?);
                // Pack a single zero
                data.push(0);
            }
        };
        Ok(data)
    }

    /// Unpacks a slice of data into a `KeystoreEntry`
    pub fn unpack(data: &[u8]) -> Result<(Self, usize), ProgramError> {
        // If the data isn't at least 12 bytes long, it's invalid
        // (discriminator, length, entry data)
        if data.len() < 12 {
            return Err(KeyringProgramError::InvalidFormatForEntry.into());
        }
        // If the first 8 bytes of the slice don't match the unique TLV
        // discriminator for a new entry, it's invalid
        if &data[0..8] != Self::SPL_DISCRIMINATOR_SLICE {
            return Err(KeyringProgramError::InvalidFormatForEntry.into());
        }
        // Read the length of the keystore entry
        let entry_length = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let entry_end = entry_length as usize + 12;
        let (key, key_data_length) = KeystoreEntryKey::unpack(&data[12..])?;
        let key_end = key_data_length + 12;
        let config = KeystoreEntryConfig::unpack(&data[key_end..])?;
        Ok((Self { key, config }, entry_end))
    }
}
