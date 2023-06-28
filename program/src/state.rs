//! Keyring Program state types

use {
    crate::{error::KeyringProgramError, tlv::KeystoreEntry},
    solana_program::{
        account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
        pubkey::Pubkey,
    },
};

/// Struct for managing a TLV structure of keystore entries.
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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Keystore {
    /// The keystore entries
    pub entries: Vec<KeystoreEntry>,
}

impl Keystore {
    /// String literal seed prefix
    const SEED_PREFIX: &'static str = "keystore";

    /// Returns the seeds for this account as a vector of slices
    pub fn seeds(authority: &Pubkey) -> Vec<&[u8]> {
        vec![Self::SEED_PREFIX.as_bytes(), authority.as_ref()]
    }

    /// Returns the program-derived address and bump seed for this account type
    /// using the provided arguments
    pub fn pda(program_id: &Pubkey, authority: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&Self::seeds(authority), program_id)
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

    /// Packs a `Keystore` into a slice of data
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        let mut data = Vec::new();
        for entry in &self.entries {
            data.extend_from_slice(&entry.pack()?);
        }
        Ok(data)
    }

    /// Unpacks a slice of data into a `Keystore`
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        // Iteratively unpack keystore entries until there is no data left
        let mut entries = vec![];
        let mut data = data;
        while !data.is_empty() {
            let (entry, entry_end) = KeystoreEntry::unpack(data)?;
            entries.push(entry);
            data = &data[entry_end..];
        }
        Ok(Self { entries })
    }

    /// Adds a new keystore entry
    pub fn add_entry(keystore_info: &AccountInfo, new_entry_data: &[u8]) -> ProgramResult {
        let (new_entry, entry_end) = KeystoreEntry::unpack(new_entry_data)?;
        // Ensure there are no leftover bytes
        if entry_end != new_entry_data.len() {
            return Err(KeyringProgramError::InvalidFormatForEntry.into());
        }
        let new_data = match keystore_info.data_is_empty() {
            true => new_entry_data.to_vec(),
            false => {
                let data = keystore_info.try_borrow_data()?;
                let mut keystore = Self::unpack(&data)?;
                keystore.entries.push(new_entry);
                keystore.pack()?
            }
        };
        realloc_and_serialize(keystore_info, &new_data)?;
        Ok(())
    }

    /// Removes a keystore entry
    pub fn remove_entry(keystore_info: &AccountInfo, remove_entry_data: &[u8]) -> ProgramResult {
        let (remove_entry, entry_end) = KeystoreEntry::unpack(remove_entry_data)?;
        // Ensure there are no leftover bytes
        if entry_end != remove_entry_data.len() {
            return Err(KeyringProgramError::InvalidFormatForEntry.into());
        }
        if keystore_info.data_is_empty() {
            return Err(KeyringProgramError::KeystoreEntryNotFound.into());
        }
        let new_data = {
            let data = keystore_info.try_borrow_data()?;
            let mut keystore = Self::unpack(&data)?;
            keystore.entries.retain(|entry| entry != &remove_entry);
            keystore.pack()?
        };
        realloc_and_serialize(keystore_info, &new_data)?;
        Ok(())
    }
}

fn realloc_and_serialize(account_info: &AccountInfo, data: &[u8]) -> ProgramResult {
    let new_len = data.len();
    account_info.realloc(new_len, true)?;
    let mut account_data_mut = account_info.try_borrow_mut_data()?;
    account_data_mut[..].copy_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::tlv::{KeystoreEntry, KeystoreEntryKey},
        solana_program::stake_history::Epoch,
        spl_discriminator::{ArrayDiscriminator, SplDiscriminate},
    };

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
    fn test_pack_unpack() {
        let curve_25519_key = vec![6; 32];

        let curve_25519_key_data = {
            let key_length = curve_25519_key.len() as u32;
            let mut buffer = Into::<[u8; 8]>::into(CURVE_25519_KEY_DISCRIMINATOR).to_vec();
            buffer.extend(key_length.to_le_bytes().to_vec());
            buffer.extend(curve_25519_key.clone());
            buffer
        };
        let curve_25519_keystore_entry_key = KeystoreEntryKey {
            discriminator: CURVE_25519_KEY_DISCRIMINATOR,
            key_length: 32,
            key: curve_25519_key,
        };
        assert_eq!(
            curve_25519_keystore_entry_key.pack().unwrap(),
            curve_25519_key_data,
            "Curve25519 key data packed incorrectly"
        );

        let curve_25519_entry_data = {
            let entry_length: u32 = curve_25519_key_data.len() as u32 + 1; // + 1 for empty `Option<T>`
            let mut buffer = Into::<[u8; 8]>::into(KeystoreEntry::SPL_DISCRIMINATOR).to_vec();
            buffer.extend(entry_length.to_le_bytes().to_vec());
            buffer.extend(curve_25519_key_data.clone());
            buffer.push(0); // Empty `Option<T>` value
            buffer
        };
        let curve_25519_keystore_entry = KeystoreEntry {
            key: curve_25519_keystore_entry_key,
            config: None,
        };
        assert_eq!(
            curve_25519_keystore_entry.pack().unwrap(),
            curve_25519_entry_data,
            "Curve25519 entry data packed incorrectly"
        );

        let rsa_key = vec![7; 32];

        let rsa_key_data = {
            let key_length = rsa_key.len() as u32;
            let mut buffer = Into::<[u8; 8]>::into(RSA_KEY_DISCRIMINATOR).to_vec();
            buffer.extend(key_length.to_le_bytes().to_vec());
            buffer.extend(rsa_key.clone());
            buffer
        };
        let rsa_keystore_entry_key = KeystoreEntryKey {
            discriminator: RSA_KEY_DISCRIMINATOR,
            key_length: 32,
            key: rsa_key,
        };
        assert_eq!(
            rsa_keystore_entry_key.pack().unwrap(),
            rsa_key_data,
            "RSA key data packed incorrectly"
        );

        let rsa_entry_data = {
            let entry_length: u32 = rsa_key_data.len() as u32 + 1; // + 1 for empty `Option<T>`
            let mut buffer = Into::<[u8; 8]>::into(KeystoreEntry::SPL_DISCRIMINATOR).to_vec();
            buffer.extend(entry_length.to_le_bytes().to_vec());
            buffer.extend(rsa_key_data.clone());
            buffer.push(0); // Empty `Option<T>` value
            buffer
        };
        let rsa_keystore_entry = KeystoreEntry {
            key: rsa_keystore_entry_key,
            config: None,
        };
        assert_eq!(
            rsa_keystore_entry.pack().unwrap(),
            rsa_entry_data,
            "RSA entry data packed incorrectly"
        );

        let keystore_data = {
            let mut buffer = vec![];
            buffer.extend(curve_25519_entry_data);
            buffer.extend(rsa_entry_data);
            buffer
        };
        let keystore = Keystore {
            entries: vec![curve_25519_keystore_entry, rsa_keystore_entry],
        };
        assert_eq!(
            keystore.pack().unwrap(),
            keystore_data,
            "Keystore data packed incorrectly"
        );
    }

    #[cfg(skip)]
    #[test]
    fn test_add_remove_key_with_account_info() {
        // Test values
        let pubkey = Pubkey::new_unique();
        let mut lamports = 0;
        let mut data = [];
        let owner = Pubkey::new_unique();

        let keystore_info = AccountInfo::new(
            &pubkey,
            false,
            true,
            &mut lamports,
            &mut data,
            &owner,
            false,
            Epoch::default(),
        );

        let curve_25519_key = vec![6; 32];
        let curve_25519_key_data = {
            let key_length = curve_25519_key.len() as u32;
            let mut buffer = Into::<[u8; 8]>::into(CURVE_25519_KEY_DISCRIMINATOR).to_vec();
            buffer.extend(key_length.to_le_bytes().to_vec());
            buffer.extend(curve_25519_key.clone());
            buffer
        };
        let curve_25519_entry_data = {
            let entry_length: u32 = curve_25519_key_data.len() as u32 + 1; // + 1 for empty `Option<T>`
            let mut buffer = Into::<[u8; 8]>::into(KeystoreEntry::SPL_DISCRIMINATOR).to_vec();
            buffer.extend(entry_length.to_le_bytes().to_vec());
            buffer.extend(curve_25519_key_data.clone());
            buffer.push(0); // Empty `Option<T>` value
            buffer
        };

        let rsa_key = vec![7; 32];
        let rsa_key_data = {
            let key_length = rsa_key.len() as u32;
            let mut buffer = Into::<[u8; 8]>::into(RSA_KEY_DISCRIMINATOR).to_vec();
            buffer.extend(key_length.to_le_bytes().to_vec());
            buffer.extend(rsa_key.clone());
            buffer
        };
        let rsa_entry_data = {
            let entry_length: u32 = rsa_key_data.len() as u32 + 1; // + 1 for empty `Option<T>`
            let mut buffer = Into::<[u8; 8]>::into(KeystoreEntryConfig::SPL_DISCRIMINATOR).to_vec();
            buffer.extend(entry_length.to_le_bytes().to_vec());
            buffer.extend(rsa_key_data.clone());
            buffer.push(0); // Empty `Option<T>` value
            buffer
        };

        Keystore::add_entry(&keystore_info, &curve_25519_entry_data)
            .expect("Failed to add Curve25519 key");
        Keystore::add_entry(&keystore_info, &rsa_entry_data).expect("Failed to add RSA key");
        assert_eq!(
            keystore_info.data_len(),
            curve_25519_entry_data.len() + rsa_entry_data.len()
        );

        Keystore::remove_entry(&keystore_info, &curve_25519_entry_data)
            .expect("Failed to remove Curve25519 key");
        assert_eq!(keystore_info.data_len(), rsa_entry_data.len());
    }
}
