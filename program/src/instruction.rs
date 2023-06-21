//! Keyring Program instructions

use {
    crate::state::Keystore,
    solana_program::{
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        pubkey::Pubkey,
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
    AddKey {
        /// Vector of bytes to be passed in as a new TLV-based keystore entry
        new_key_data: Vec<u8>,
    },
    /// Remove a key from the keystore
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keystore
    ///   1. `[s]` Authority
    RemoveKey {
        /// Vector of bytes to be passed in as the TLV-based keystore entry to
        /// delete
        remove_key_data: Vec<u8>,
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
            KeyringProgramInstruction::AddKey { new_key_data: _ } => {
                buf.push(1);
            }
            KeyringProgramInstruction::RemoveKey { remove_key_data: _ } => {
                buf.push(2);
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
            1 => KeyringProgramInstruction::AddKey {
                new_key_data: rest.to_vec(),
            },
            2 => KeyringProgramInstruction::RemoveKey {
                remove_key_data: rest.to_vec(),
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
        AccountMeta::new(keystore, true),
        AccountMeta::new(*authority, true),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Creates an 'AddKey' instruction.
pub fn add_key(
    program_id: &Pubkey,
    authority: &Pubkey,
    new_key_data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let keystore = Keystore::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::AddKey { new_key_data }.pack();

    let accounts = vec![
        AccountMeta::new(keystore, true),
        AccountMeta::new(*authority, true),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Creates a 'RemoveKey' instruction.
pub fn remove_key(
    program_id: &Pubkey,
    authority: &Pubkey,
    remove_key_data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let keystore = Keystore::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::RemoveKey { remove_key_data }.pack();

    let accounts = vec![
        AccountMeta::new(keystore, true),
        AccountMeta::new(*authority, true),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}
