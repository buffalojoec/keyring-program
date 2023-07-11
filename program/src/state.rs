//! Keyring Program state

use solana_program::{program_error::ProgramError, pubkey::Pubkey};

/// Struct for managing keystore state
pub struct Keyring;
impl Keyring {
    /// String literal seed prefix
    const SEED_PREFIX: &'static str = "keyring";

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seeds() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let seeds = Keyring::seeds(&authority);
        let (pda, bump_seed) = Keyring::pda(&program_id, &authority);
        let check_seeds = [b"keyring", authority.as_ref()];
        let check_pda = Pubkey::find_program_address(&check_seeds, &program_id);
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0], Keyring::SEED_PREFIX.as_bytes());
        assert_eq!(seeds[0], check_seeds[0]);
        assert_eq!(seeds[1], check_seeds[1]);
        assert_eq!(pda, check_pda.0);
        assert_eq!(bump_seed, check_pda.1);
    }
}
