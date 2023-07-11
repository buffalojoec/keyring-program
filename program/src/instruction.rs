//! Keyring Program instructions

use {
    crate::state::Keyring,
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
    /// Create a new keyring account for the keystore
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keyring
    ///   1. `[s]` Authority
    CreateKeyring,
    /// Update the keyring with new data
    ///
    /// This can either add or remove a key from the keystore.
    /// Since all serialization is off-chain, the program will write whatever
    /// bytes are passed into this instruction to the keystore, and overwrite
    /// the entire data buffer of the keyring account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keyring
    ///   1. `[s]` Authority
    UpdateKeyring {
        /// Vector of bytes to be passed in as a new TLV-based keystore entry
        data: Vec<u8>,
    },
}

impl KeyringProgramInstruction {
    /// Packs a `KeyringProgramInstruction` into a byte array.
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            KeyringProgramInstruction::CreateKeyring {} => {
                buf.push(0);
            }
            KeyringProgramInstruction::UpdateKeyring { data } => {
                buf.push(1);
                buf.extend_from_slice(data);
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
            0 => KeyringProgramInstruction::CreateKeyring,
            1 => KeyringProgramInstruction::UpdateKeyring {
                data: rest.to_vec(),
            },
            _ => return Err(ProgramError::InvalidInstructionData),
        })
    }
}

/// Creates a 'CreateKeyring' instruction.
pub fn create_keyring(
    program_id: &Pubkey,
    authority: &Pubkey,
) -> Result<Instruction, ProgramError> {
    let keyring = Keyring::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::CreateKeyring {}.pack();

    let accounts = vec![
        AccountMeta::new(keyring, false),
        AccountMeta::new(*authority, true),
        AccountMeta::new(system_program::id(), false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Creates an 'UpdateKeyring' instruction.
pub fn update_keyring(
    program_id: &Pubkey,
    authority: &Pubkey,
    data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let keyring = Keyring::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::UpdateKeyring { data }.pack();

    let accounts = vec![
        AccountMeta::new(keyring, false),
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
    fn create_keyring_instruction() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        let instruction = create_keyring(&program_id, &authority).unwrap();
        assert_eq!(
            instruction.data,
            KeyringProgramInstruction::CreateKeyring {}.pack()
        );
    }

    #[test]
    fn update_keyring_instruction() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let data = vec![1, 2, 3];

        let instruction = update_keyring(&program_id, &authority, data.clone()).unwrap();
        assert_eq!(
            instruction.data,
            KeyringProgramInstruction::UpdateKeyring { data }.pack()
        );
    }
}
