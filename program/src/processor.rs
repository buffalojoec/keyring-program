//! Program processor

use {
    crate::{
        instruction::KeyringProgramInstruction,
        state::{AlgorithmStore, Keystore},
    },
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        msg,
        program_error::ProgramError,
        pubkey::Pubkey,
    },
};

fn check_authority(authority_info: &AccountInfo) -> ProgramResult {
    if !authority_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

/// Processes a `InitializeAlgorithmStore` instruction.
pub fn process_initialize_algorithm_store(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let algorithm_store_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;

    AlgorithmStore::check_pda(program_id, algorithm_store_info.key)?;
    check_authority(authority_info)?;

    Ok(())
}

/// Processes a `AddAlgorithm` instruction.
pub fn process_add_algorithm(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let algorithm_store_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;

    AlgorithmStore::check_pda(program_id, algorithm_store_info.key)?;
    check_authority(authority_info)?;

    Ok(())
}

/// Processes a `RemoveAlgorithm` instruction.
pub fn process_remove_algorithm(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let algorithm_store_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;

    AlgorithmStore::check_pda(program_id, algorithm_store_info.key)?;
    check_authority(authority_info)?;

    Ok(())
}

/// Processes a `CreateKeystore` instruction.
pub fn process_create_keystore(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let keystore_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;

    Keystore::check_pda(program_id, authority_info.key, keystore_info.key)?;
    check_authority(authority_info)?;

    Ok(())
}

/// Processes a `AddKey` instruction.
pub fn process_add_key(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let keystore_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;

    Keystore::check_pda(program_id, authority_info.key, keystore_info.key)?;
    check_authority(authority_info)?;

    Ok(())
}

/// Processes a `RemoveKey` instruction.
pub fn process_remove_key(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let keystore_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;

    Keystore::check_pda(program_id, authority_info.key, keystore_info.key)?;
    check_authority(authority_info)?;

    Ok(())
}

/// Processes a `KeyringProgramInstruction` instruction.
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], input: &[u8]) -> ProgramResult {
    let instruction = KeyringProgramInstruction::unpack(input)?;

    match instruction {
        KeyringProgramInstruction::InitializeAlgorithmStore {} => {
            msg!("Instruction: InitializeAlgorithmStore");
            process_initialize_algorithm_store(program_id, accounts)
        }
        KeyringProgramInstruction::AddAlgorithm {} => {
            msg!("Instruction: AddAlgorithm");
            process_add_algorithm(program_id, accounts)
        }
        KeyringProgramInstruction::RemoveAlgorithm {} => {
            msg!("Instruction: RemoveAlgorithm");
            process_remove_algorithm(program_id, accounts)
        }
        KeyringProgramInstruction::CreateKeystore {} => {
            msg!("Instruction: CreateKeystore");
            process_create_keystore(program_id, accounts)
        }
        KeyringProgramInstruction::AddKey {} => {
            msg!("Instruction: AddKey");
            process_add_key(program_id, accounts)
        }
        KeyringProgramInstruction::RemoveKey {} => {
            msg!("Instruction: RemoveKey");
            process_remove_key(program_id, accounts)
        }
    }
}
