//! The Keyring Program Client

use {
    crate::error::KeyringError,
    solana_sdk::{
        account::Account, instruction::Instruction, message::Message, pubkey::Pubkey,
        signature::Keypair, signer::Signer, signers::Signers, transaction::Transaction,
    },
    spl_keyring_program::{state::Keystore, tlv::KeystoreEntry},
    spl_token_client::client::{ProgramClient, SendTransaction},
    std::{fmt, sync::Arc},
};

/// The Keyring Program Client
pub struct Keyring<T> {
    client: Arc<dyn ProgramClient<T>>,
    payer: Arc<dyn Signer>,
    program_id: Pubkey,
}

impl<T> fmt::Debug for Keyring<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("payer", &self.payer.pubkey())
            .field("program_id", &self.program_id)
            .finish()
    }
}

impl<T> Keyring<T>
where
    T: SendTransaction,
{
    /// Create a new instance of the Keyring Program Client
    pub fn new(
        client: Arc<dyn ProgramClient<T>>,
        program_id: &Pubkey,
        payer: Arc<dyn Signer>,
    ) -> Self {
        Keyring {
            client,
            payer,
            program_id: *program_id,
        }
    }

    /// Fetch the keystore account
    pub async fn get_keystore_account(&self, authority: &Pubkey) -> Result<Account, KeyringError> {
        self.client
            .get_account(*authority)
            .await
            .map_err(KeyringError::Client)?
            .ok_or(KeyringError::KeystoreNotFound)
    }

    /// Fetch the keystore account, unpacked
    pub async fn get_keystore(&self, authority: &Pubkey) -> Result<Keystore, KeyringError> {
        let keystore_account = self.get_keystore_account(authority).await?;
        Keystore::unpack(&keystore_account.data).map_err(KeyringError::Program)
    }

    /// Construct a transaction from a list of instructions
    async fn construct_tx<S: Signers>(
        &self,
        token_instructions: &[Instruction],
        signing_keypairs: &S,
    ) -> Result<Transaction, KeyringError> {
        let mut instructions = vec![];
        let payer_key = self.payer.pubkey();
        let fee_payer = Some(&payer_key);

        instructions.extend_from_slice(token_instructions);

        let (message, blockhash) = {
            let latest_blockhash = self
                .client
                .get_latest_blockhash()
                .await
                .map_err(KeyringError::Client)?;
            (
                Message::new_with_blockhash(&instructions, fee_payer, &latest_blockhash),
                latest_blockhash,
            )
        };

        let mut transaction = Transaction::new_unsigned(message);

        transaction
            .try_partial_sign(&vec![self.payer.clone()], blockhash)
            .map_err(|error| KeyringError::Client(error.into()))?;
        transaction
            .try_partial_sign(signing_keypairs, blockhash)
            .map_err(|error| KeyringError::Client(error.into()))?;

        Ok(transaction)
    }

    /// Construct a transaction from a list of instructions
    pub async fn process_ixs<S: Signers>(
        &self,
        token_instructions: &[Instruction],
        signing_keypairs: &S,
    ) -> Result<(), KeyringError> {
        let transaction = self
            .construct_tx(token_instructions, signing_keypairs)
            .await?;

        self.client
            .send_transaction(&transaction)
            .await
            .map_err(KeyringError::Client)?;

        Ok(())
    }

    /// Create a new keystore
    pub async fn create_keystore(&self, authority: &Keypair) -> Result<(), KeyringError> {
        let ix = spl_keyring_program::instruction::create_keystore(
            &spl_keyring_program::id(),
            &authority.pubkey(),
        )?;
        self.process_ixs(&[ix], &[authority]).await
    }

    /// Add a new key to a keystore
    pub async fn add_entry(
        &self,
        authority: &Keypair,
        entry: KeystoreEntry,
    ) -> Result<(), KeyringError> {
        let ix = spl_keyring_program::instruction::add_entry(
            &spl_keyring_program::id(),
            &authority.pubkey(),
            entry.pack().map_err(KeyringError::Program)?,
        )?;
        self.process_ixs(&[ix], &[authority]).await
    }

    /// Remove a key from a keystore
    pub async fn remove_entry(
        &self,
        authority: &Keypair,
        entry: KeystoreEntry,
    ) -> Result<(), KeyringError> {
        let ix = spl_keyring_program::instruction::remove_entry(
            &spl_keyring_program::id(),
            &authority.pubkey(),
            entry.pack().map_err(KeyringError::Program)?,
        )?;
        self.process_ixs(&[ix], &[authority]).await
    }
}
