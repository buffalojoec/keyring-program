//! Keyring Program instructions

use {
    crate::state::{AlgorithmStore, Keystore},
    solana_program::{
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        pubkey::Pubkey,
    },
};

/// Keyring Program instructions.
#[derive(Clone, Debug, PartialEq)]
pub enum KeyringProgramInstruction {
    /// Initialize the algorithm store
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` AlgorithmStore
    ///   1. `[s]` MultiSig Authority
    InitializeAlgorithmStore {},
    /// Add an algorithm to the algorithm store
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` AlgorithmStore
    ///   1. `[s]` MultiSig Authority
    AddAlgorithm {},
    /// Remove an algorithm from the algorithm store
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` AlgorithmStore
    ///   1. `[s]` MultiSig Authority
    RemoveAlgorithm {},
    /// Create a new keystore
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keystore
    ///   1. `[s]` Authority
    CreateKeystore {},
    /// Add a key to the keystore
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keystore
    ///   1. `[s]` Authority
    AddKey {},
    /// Remove a key from the keystore
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[w]` Keystore
    ///   1. `[s]` Authority
    RemoveKey {},
}

impl KeyringProgramInstruction {
    /// Packs a `KeyringProgramInstruction` into a byte array.
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            KeyringProgramInstruction::InitializeAlgorithmStore {} => {
                buf.push(0);
            }
            KeyringProgramInstruction::AddAlgorithm {} => {
                buf.push(1);
            }
            KeyringProgramInstruction::RemoveAlgorithm {} => {
                buf.push(2);
            }
            KeyringProgramInstruction::CreateKeystore {} => {
                buf.push(3);
            }
            KeyringProgramInstruction::AddKey {} => {
                buf.push(4);
            }
            KeyringProgramInstruction::RemoveKey {} => {
                buf.push(5);
            }
        }
        buf
    }

    /// Unpacks a byte buffer into a `KeyringProgramInstruction`.
    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let instruction = match input[0] {
            0 => KeyringProgramInstruction::InitializeAlgorithmStore {},
            1 => KeyringProgramInstruction::AddAlgorithm {},
            2 => KeyringProgramInstruction::RemoveAlgorithm {},
            3 => KeyringProgramInstruction::CreateKeystore {},
            4 => KeyringProgramInstruction::AddKey {},
            5 => KeyringProgramInstruction::RemoveKey {},
            _ => return Err(ProgramError::InvalidInstructionData),
        };
        Ok(instruction)
    }
}

/// Creates an 'InitializeAlgorithmStore' instruction.
pub fn initialize_algorithm_store(
    program_id: &Pubkey,
    authority: &Pubkey,
    _data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let algorithm_store = AlgorithmStore::pda(program_id).0;

    let data = KeyringProgramInstruction::InitializeAlgorithmStore {}.pack();

    let accounts = vec![
        AccountMeta::new(algorithm_store, true),
        AccountMeta::new_readonly(*authority, false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Creates an 'AddAlgorithm' instruction.
pub fn add_algorithm(
    program_id: &Pubkey,
    authority: &Pubkey,
    _data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let algorithm_store = AlgorithmStore::pda(program_id).0;

    let data = KeyringProgramInstruction::AddAlgorithm {}.pack();

    let accounts = vec![
        AccountMeta::new(algorithm_store, true),
        AccountMeta::new(*authority, true),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Creates a 'RemoveAlgorithm' instruction.
pub fn remove_algorithm(
    program_id: &Pubkey,
    authority: &Pubkey,
    _data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let algorithm_store = AlgorithmStore::pda(program_id).0;

    let data = KeyringProgramInstruction::RemoveAlgorithm {}.pack();

    let accounts = vec![
        AccountMeta::new(algorithm_store, true),
        AccountMeta::new(*authority, true),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Creates a 'CreateKeystore' instruction.
pub fn create_keystore(
    program_id: &Pubkey,
    authority: &Pubkey,
    _data: Vec<u8>,
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
    _data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let keystore = Keystore::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::AddKey {}.pack();

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
    _data: Vec<u8>,
) -> Result<Instruction, ProgramError> {
    let keystore = Keystore::pda(program_id, authority).0;

    let data = KeyringProgramInstruction::AddKey {}.pack();

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
