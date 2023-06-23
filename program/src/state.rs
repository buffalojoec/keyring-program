//! Keyring Program state types

use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::{entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey},
    spl_discriminator::ArrayDiscriminator,
};

/// The TLV discriminator marking a new keystore entry: [1, 1, 1, 1, 1, 1, 1, 1]
const ENTRY_DISCRIMINATOR: ArrayDiscriminator = ArrayDiscriminator::new([1u8; 8]);
/// The TLV discriminator marking additional configurations for a keystore
/// entry: [2, 2, 2, 2, 2, 2, 2, 2]
const CONFIGURATION_DISCRIMINATOR: ArrayDiscriminator = ArrayDiscriminator::new([2u8; 8]);

/// Key-value entry for additional encryption algorithm configurations
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct KeystoreEntryConfigEntry {
    /// Configuration key discriminator
    pub key_discriminator: ArrayDiscriminator,
    /// Length of the configuration value
    pub value_length: u32,
    /// Configuration value
    pub value: Vec<u8>,
}
impl KeystoreEntryConfigEntry {
    /// Creates a new `KeystoreEntryConfigEntry` from provided key
    /// discriminator and value
    pub fn new(key_discriminator: ArrayDiscriminator, value: Vec<u8>) -> Self {
        let value_length = value.len() as u32;
        Self {
            key_discriminator: key_discriminator.into(),
            value_length,
            value,
        }
    }
}

/// Configurations section in a keystore entry
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct KeystoreEntryConfig {
    /// Configuration discriminator
    pub config_discriminator: ArrayDiscriminator,
    /// Length of the configuration section
    pub config_length: u32,
    /// Vector of configuration entries
    pub entries: Vec<KeystoreEntryConfigEntry>,
}
impl KeystoreEntryConfig {
    /// Creates a new `KeystoreEntryConfig` from provided configuration entries
    pub fn new(entries: Vec<KeystoreEntryConfigEntry>) -> Self {
        let config_length = entries
            .iter()
            .fold(0, |acc, e| acc + 8 + 4 + e.value_length);
        Self {
            config_discriminator: CONFIGURATION_DISCRIMINATOR.into(),
            config_length,
            entries,
        }
    }
}

/// Key section in a keystore entry
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct KeystoreEntryKey {
    /// Key discriminator (encryption algorithm)
    pub key_discriminator: ArrayDiscriminator,
    /// Length of the encryption key
    pub key_length: u32,
    /// Encryption key
    pub key: Vec<u8>,
}
impl KeystoreEntryKey {
    /// Creates a new `KeystoreEntryKey` from provided key discriminator and
    /// key
    pub fn new(key_discriminator: ArrayDiscriminator, key: Vec<u8>) -> Self {
        let key_length = key.len() as u32;
        Self {
            key_discriminator: key_discriminator.into(),
            key_length,
            key,
        }
    }
}

/// A keystore entry
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct KeystoreEntry {
    /// Entry discriminator
    pub entry_discriminator: ArrayDiscriminator,
    /// Length of the entry
    pub entry_length: u32,
    /// Encryption key
    pub key: KeystoreEntryKey,
    /// Additional configurations
    pub config: Option<KeystoreEntryConfig>,
}
impl KeystoreEntry {
    /// Creates a new `KeystoreEntry` from provided key and optional
    /// configuration
    pub fn new(key: KeystoreEntryKey, config: Option<KeystoreEntryConfig>) -> Self {
        let entry_length =
            8 + 4 + key.key_length + config.as_ref().map_or(1, |c| 8 + 4 + c.config_length);
        Self {
            entry_discriminator: ENTRY_DISCRIMINATOR.into(),
            entry_length,
            key,
            config,
        }
    }
}

/// Struct for managing a vector of keystore entries.
///
/// The data within a keystore account is managed using nested TLV entries.
/// * T: The new entry discriminator (marks the start of a new keystore entry)
/// * L: The length of the entry
/// * V: The data of the entry
///     * (Encryption key)
///         * T: The algorithm discriminator (provided by sRFC workflow)
///         * L: The length of the key
///         * V: The key itself
///     * (Additional configurations)
///         * T: The configuration discriminator (marks additional
///           configurations are present)
///         * L: The total length of the configuration data
///         * V: The configuration data
///             * (Configuration: `K, V`)
///                 * T: The configuration key (provided by sRFC workflow)
///                 * L: The configuration value length
///                 * T: The configuration value
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct Keystore {
    entries: Vec<KeystoreEntry>,
}
impl Keystore {
    /// String literal seed prefix
    const SEED_PREFIX: &'static str = "keystore";

    /// Returns the seeds for this account as a vector of slices
    pub fn seeds<'s>(authority: &'s Pubkey) -> Vec<&'s [u8]> {
        vec![Self::SEED_PREFIX.as_bytes(), authority.as_ref()]
    }

    /// Returns the program-derived address and bump seed for this account type
    /// using the provided arguments
    pub fn pda(program_id: &Pubkey, authority: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&Self::seeds(authority), program_id)
    }

    /// Creates a new, empty `Keystore`
    pub fn new() -> Self {
        Self { entries: vec![] }
    }

    /// Validates a passed `Pubkey` against the `Pubkey` returned from the
    /// `pda(&self, ..)` method, then returns the bump seed
    pub fn check_pda(
        program_id: &Pubkey,
        authority: &Pubkey,
        pda: &Pubkey,
    ) -> Result<u8, ProgramError> {
        let (pda_check, bump_seed) = Self::pda(program_id, authority);
        if pda != &pda_check {
            return Err(ProgramError::InvalidSeeds);
        }
        Ok(bump_seed)
    }

    /// Adds a new keystore entry
    pub fn add_entry(&mut self, add_key_data: Vec<u8>) -> ProgramResult {
        let add_key = KeystoreEntry::try_from_slice(&add_key_data)?;
        self.entries.push(add_key);
        Ok(())
    }

    /// Removes a keystore entry
    pub fn remove_entry(&mut self, remove_key_data: Vec<u8>) -> ProgramResult {
        let remove_key = KeystoreEntry::try_from_slice(&remove_key_data)?;
        self.entries.retain(|entry| entry != &remove_key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURVE_25519_KEY_DISCRIMINATOR: ArrayDiscriminator =
        ArrayDiscriminator::new([2, 2, 2, 2, 2, 2, 2, 2]);
    const RSA_KEY_DISCRIMINATOR: ArrayDiscriminator =
        ArrayDiscriminator::new([3, 3, 3, 3, 3, 3, 3, 3]);

    #[test]
    fn test_seeds() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let seeds = Keystore::seeds(&authority);
        let (pda, bump_seed) = Keystore::pda(&program_id, &authority);
        let check_seeds = [b"keystore", authority.as_ref()];
        let check_pda = Pubkey::find_program_address(&check_seeds, &program_id);
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0], Keystore::SEED_PREFIX.as_bytes());
        assert_eq!(seeds[0], check_seeds[0]);
        assert_eq!(seeds[1], check_seeds[1]);
        assert_eq!(pda, check_pda.0);
        assert_eq!(bump_seed, check_pda.1);
    }

    #[test]
    fn test_add_remove_key() {
        let curve_25519_key = vec![6; 32];
        let curve_25519_key_data = {
            let mut buffer = Into::<[u8; 8]>::into(CURVE_25519_KEY_DISCRIMINATOR).to_vec();
            let key_length = curve_25519_key.len() as u32 + 4;
            buffer.extend(key_length.to_le_bytes().to_vec());
            buffer.extend((curve_25519_key.len() as u32).to_le_bytes().to_vec()); // Vector len for borsh
            buffer.extend(curve_25519_key.clone());
            buffer
        };
        let curve_25519_entry_data = {
            let mut buffer = Into::<[u8; 8]>::into(ENTRY_DISCRIMINATOR).to_vec();
            let entry_length: u32 = curve_25519_key_data.len() as u32 + 1;
            buffer.extend(entry_length.to_le_bytes().to_vec());
            buffer.extend(curve_25519_key_data.clone());
            buffer.push(0); // Empty `Option<T>` value
            buffer
        };

        let rsa_key = vec![7; 32];
        let rsa_key_data = {
            let mut buffer = Into::<[u8; 8]>::into(RSA_KEY_DISCRIMINATOR).to_vec();
            let key_length = rsa_key.len() as u32 + 4;
            buffer.extend(key_length.to_le_bytes().to_vec());
            buffer.extend((rsa_key.len() as u32).to_le_bytes().to_vec()); // Vector len for borsh
            buffer.extend(rsa_key.clone());
            buffer
        };
        let rsa_entry_data = {
            let mut buffer = Into::<[u8; 8]>::into(ENTRY_DISCRIMINATOR).to_vec();
            let entry_length: u32 = rsa_key_data.len() as u32 + 1;
            buffer.extend(entry_length.to_le_bytes().to_vec());
            buffer.extend(rsa_key_data.clone());
            buffer.push(0); // Empty `Option<T>` value
            buffer
        };

        let test_entry = KeystoreEntry::new(
            KeystoreEntryKey {
                key_discriminator: CURVE_25519_KEY_DISCRIMINATOR,
                key_length: 32,
                key: curve_25519_key.clone(),
            },
            None,
        );
        let test_keystore = Keystore {
            entries: vec![test_entry.clone()],
        };
        println!(
            "TEST KEYSTORE LEN: {}",
            test_keystore.try_to_vec().unwrap().len()
        );
        println!("TEST ENTRY LEN: {}", test_entry.try_to_vec().unwrap().len());
        println!("CURVE 25519 ENTRY LEN: {}", curve_25519_entry_data.len());
        println!("CURVE 25519 ENTRY: {:?}", curve_25519_entry_data);

        let mut keystore = Keystore::new();
        keystore
            .add_entry(curve_25519_entry_data.clone())
            .expect("Failed to add Curve25519 key");
        keystore
            .add_entry(rsa_entry_data.clone())
            .expect("Failed to add RSA key");
        assert_eq!(keystore.entries.len(), 2);
        assert_eq!(&keystore.entries[0].key.key, &curve_25519_key);
        assert_eq!(&keystore.entries[1].key.key, &rsa_key);

        keystore
            .remove_entry(curve_25519_entry_data)
            .expect("Failed to remove Curve25519 key");
        assert_eq!(keystore.entries.len(), 1);
        assert_eq!(&keystore.entries[0].key.key, &rsa_key);
    }
}
