//! Program processor

use {
    crate::{instruction::KeyringProgramInstruction, state::Keyring},
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

/// Processes a `CreateKeyring` instruction.
pub fn process_create_keyring(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let keyring_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let bump_seed = {
        check_authority(authority_info)?;
        Keyring::check_pda(program_id, authority_info.key, keyring_info.key)?
    };

    let mut signer_seeds = Keyring::seeds(authority_info.key);
    let bump_signer_seed = [bump_seed];
    signer_seeds.push(&bump_signer_seed);

    invoke_signed(
        &system_instruction::create_account(
            authority_info.key,
            keyring_info.key,
            Rent::default().minimum_balance(0),
            0u64,
            program_id,
        ),
        &[authority_info.clone(), keyring_info.clone()],
        &[&signer_seeds],
    )?;

    Ok(())
}

/// Processes a `UpdateKeyring` instruction.
///
/// Simply overwrites the entire account buffer with the new data.
pub fn process_update_keyring(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: Vec<u8>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let keyring_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;

    {
        Keyring::check_pda(program_id, authority_info.key, keyring_info.key)?;
        check_authority(authority_info)?;
    }

    let new_len = data.len();
    keyring_info.realloc(new_len, true)?;
    keyring_info.try_borrow_mut_data()?[..].copy_from_slice(&data);

    Ok(())
}

/// Processes a `KeyringProgramInstruction` instruction.
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], input: &[u8]) -> ProgramResult {
    let instruction = KeyringProgramInstruction::unpack(input)?;

    match instruction {
        KeyringProgramInstruction::CreateKeyring {} => {
            msg!("Instruction: CreateKeyring");
            process_create_keyring(program_id, accounts)
        }
        KeyringProgramInstruction::UpdateKeyring { data } => {
            msg!("Instruction: UpdateKeyring");
            process_update_keyring(program_id, accounts, data)
        }
    }
}
