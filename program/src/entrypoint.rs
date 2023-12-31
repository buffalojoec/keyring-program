//! Program entrypoint

use {
    crate::processor,
    solana_program::{
        account_info::AccountInfo,
        entrypoint,
        entrypoint::ProgramResult, 
        pubkey::Pubkey,
    },
};

entrypoint!(process_instruction);
fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    processor::process(program_id, accounts, instruction_data)?;
    Ok(())
}
