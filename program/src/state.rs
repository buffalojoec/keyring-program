//! Keyring Program state types

use {
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey},
};

/// Data struct for a keystore
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct Keystore {
    /// TODO!
    pub keys: Vec<u8>,
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

    /// Validates a passed `Pubkey` against the `Pubkey` returned from the
    /// `pda(&self, ..)` method
    pub fn check_pda(program_id: &Pubkey, authority: &Pubkey, pda: &Pubkey) -> ProgramResult {
        let (pda_check, _) = Self::pda(program_id, authority);
        if pda != &pda_check {
            return Err(ProgramError::InvalidSeeds);
        }
        Ok(())
    }
}

/// Data struct for an algorithm store
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct AlgorithmStore {
    /// TODO!
    pub keys: Vec<u8>,
}

impl AlgorithmStore {
    /// String literal seed prefix
    const SEED_PREFIX: &'static str = "algorithm_store";

    /// Returns the seeds for this account as a vector of slices
    pub fn seeds<'s>() -> Vec<&'s [u8]> {
        vec![Self::SEED_PREFIX.as_bytes()]
    }

    /// Returns the program-derived address and bump seed for this account type
    /// using the provided arguments
    pub fn pda(program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&Self::seeds(), program_id)
    }

    /// Validates a passed `Pubkey` against the `Pubkey` returned from the
    /// `pda(&self, ..)` method
    pub fn check_pda(program_id: &Pubkey, pda: &Pubkey) -> ProgramResult {
        let (pda_check, _) = Self::pda(program_id);
        if pda != &pda_check {
            return Err(ProgramError::InvalidSeeds);
        }
        Ok(())
    }
}
