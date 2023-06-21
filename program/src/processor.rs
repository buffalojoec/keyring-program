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
        program::invoke_signed,
        program_error::ProgramError,
        pubkey::Pubkey,
        rent::Rent,
        system_instruction,
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

    let bump_seed = {
        check_authority(authority_info)?;
        AlgorithmStore::check_pda(program_id, algorithm_store_info.key)?
    };

    let algorithm_store = [0u8; 8]; // TODO!

    let space = algorithm_store.len();
    let lamports = Rent::default().minimum_balance(space);
    let mut signer_seeds = AlgorithmStore::seeds();
    let bump_signer_seed = [bump_seed];
    signer_seeds.push(&bump_signer_seed);

    invoke_signed(
        &system_instruction::create_account(
            authority_info.key,
            algorithm_store_info.key,
            lamports,
            space as u64,
            program_id,
        ),
        &[authority_info.clone(), algorithm_store_info.clone()],
        &[&signer_seeds],
    )
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

    let bump_seed = {
        check_authority(authority_info)?;
        Keystore::check_pda(program_id, authority_info.key, keystore_info.key)?
    };

    let keystore = [0u8; 8]; // TODO!

    let space = keystore.len();
    let lamports = Rent::default().minimum_balance(space);
    let mut signer_seeds = Keystore::seeds(authority_info.key);
    let bump_signer_seed = [bump_seed];
    signer_seeds.push(&bump_signer_seed);

    invoke_signed(
        &system_instruction::create_account(
            authority_info.key,
            keystore_info.key,
            lamports,
            space as u64,
            program_id,
        ),
        &[authority_info.clone(), keystore_info.clone()],
        &[&signer_seeds],
    )
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
