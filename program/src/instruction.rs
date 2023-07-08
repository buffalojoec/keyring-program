//! Keyring Program instructions

use {
    crate::state::Keystore,
    solana_program::{
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        pubkey::Pubkey,
        system_program,
    },
};

/// Keyring Program instructions.
#[derive(Clone, Debug, PartialEq)]
pub enum KeyringProgramInstruction {
    /// Create a new keystore
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keystore
    ///   1. `[s]` Authority
    CreateKeystore,
    /// Add a key to the keystore
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keystore
    ///   1. `[s]` Authority
    AddEntry {
        /// Vector of bytes to be passed in as a new TLV-based keystore entry
        add_entry_data: Vec<u8>,
    },
    /// Remove a key from the keystore
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keystore
    ///   1. `[s]` Authority
    RemoveEntry {
        /// Vector of bytes to be passed in as the TLV-based keystore entry to
        /// delete
        remove_entry_data: Vec<u8>,
    },
}

impl KeyringProgramInstruction {
    /// Packs a `KeyringProgramInstruction` into a byte array.
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            KeyringProgramInstruction::CreateKeystore {} => {
                buf.push(0);
            }
            KeyringProgramInstruction::AddEntry { add_entry_data } => {
                buf.push(1);
                buf.extend_from_slice(add_entry_data);
            }
            KeyringProgramInstruction::RemoveEntry { remove_entry_data } => {
                buf.push(2);
                buf.extend_from_slice(remove_entry_data);
            }
        }
        buf
    }

    /// Unpacks a byte buffer into a `KeyringProgramInstruction`.
    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let (instruction, rest) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        Ok(match instruction {
            0 => KeyringProgramInstruction::CreateKeystore,
            1 => KeyringProgramInstruction::AddEntry {
                add_entry_data: rest.to_vec(),
            },
            2 => KeyringProgramInstruction::RemoveEntry {
                remove_entry_data: rest.to_vec(),
            },
            _ => return Err(ProgramError::InvalidInstructionData),
        })
    }
}

/// Creates a 'CreateKeystore' instruction.
pub fn create_keystore(
    program_id: &Pubkey,
    authority: &Pubkey,
) -> Result<Instruction, ProgramError> {
    let keystore = Keystore::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::CreateKeystore {}.pack();

    let accounts = vec![
        AccountMeta::new(keystore, false),
        AccountMeta::new(*authority, true),
        AccountMeta::new(system_program::id(), false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Creates an 'AddKey' instruction.
pub fn add_entry(
    program_id: &Pubkey,
    authority: &Pubkey,
    add_entry_data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let keystore = Keystore::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::AddEntry { add_entry_data }.pack();

    let accounts = vec![
        AccountMeta::new(keystore, false),
        AccountMeta::new(*authority, true),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Creates a 'RemoveKey' instruction.
pub fn remove_entry(
    program_id: &Pubkey,
    authority: &Pubkey,
    remove_entry_data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let keystore = Keystore::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::RemoveEntry { remove_entry_data }.pack();

    let accounts = vec![
        AccountMeta::new(keystore, false),
        AccountMeta::new(*authority, true),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_keystore() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        let instruction = create_keystore(&program_id, &authority).unwrap();
        assert_eq!(
            instruction.data,
            KeyringProgramInstruction::CreateKeystore {}.pack()
        );
    }

    #[test]
    fn test_add_entry() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let add_entry_data = vec![1, 2, 3];

        let instruction = add_entry(&program_id, &authority, add_entry_data.clone()).unwrap();
        assert_eq!(
            instruction.data,
            KeyringProgramInstruction::AddEntry { add_entry_data }.pack()
        );
    }

    #[test]
    fn test_remove_entry() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let remove_entry_data = vec![1, 2, 3];

        let instruction = remove_entry(&program_id, &authority, remove_entry_data.clone()).unwrap();
        assert_eq!(
            instruction.data,
            KeyringProgramInstruction::RemoveEntry { remove_entry_data }.pack()
        );
    }
}
