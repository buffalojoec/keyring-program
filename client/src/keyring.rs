use {
    crate::client::{ProgramClient, SendTransaction},
    solana_sdk::{pubkey::Pubkey, signer::Signer},
    std::{fmt, sync::Arc},
};

pub struct Keyring<T> {
    client: Arc<dyn ProgramClient<T>>,
    keystore: Pubkey,
    algorithm_store: Pubkey,
    authority: Arc<dyn Signer>,
    program_id: Pubkey,
}

impl<T> fmt::Debug for Keyring<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("keystore", &self.keystore)
            .field("algorithm_store", &self.algorithm_store)
            .field("authority", &self.authority.pubkey())
            .field("program_id", &self.program_id)
            .finish()
    }
}

impl<T> Keyring<T>
where
    T: SendTransaction,
{
    pub fn new(
        client: Arc<dyn ProgramClient<T>>,
        keystore: Pubkey,
        algorithm_store: Pubkey,
        authority: Arc<dyn Signer>,
        program_id: Pubkey,
    ) -> Self {
        Self {
            client,
            keystore,
            algorithm_store,
            authority,
            program_id,
        }
    }
}
