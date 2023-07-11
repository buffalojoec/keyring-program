//! The Keyring Program Client

use {
    crate::{
        error::KeyringError,
        keystore::{EncryptionKeyConfig, Keystore},
    },
    borsh::{BorshDeserialize, BorshSerialize},
    solana_sdk::{
        account::Account, instruction::Instruction, message::Message, pubkey::Pubkey,
        signature::Keypair, signer::Signer, signers::Signers, transaction::Transaction,
    },
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

    /// Get the users's keyring address
    pub fn get_keyring_address(&self, authority: &Pubkey) -> (Pubkey, u8) {
        spl_keyring_program::state::Keyring::pda(&self.program_id, authority)
    }

    /// Fetch the user's keyring account
    pub async fn get_keyring_account(&self, authority: &Pubkey) -> Result<Account, KeyringError> {
        self.client
            .get_account(self.get_keyring_address(authority).0)
            .await
            .map_err(KeyringError::Client)?
            .ok_or(KeyringError::KeystoreNotFound)
    }

    /// Fetch the user's keyring account, unpacked
    pub async fn get_keystore(&self, authority: &Pubkey) -> Result<Keystore, KeyringError> {
        let keyring_account = self.get_keyring_account(authority).await?;
        if keyring_account.data.is_empty() {
            Ok(Keystore::default())
        } else {
            Keystore::try_from_slice(&keyring_account.data)
                .map_err(|e| KeyringError::Program(e.into()))
        }
    }

    /// Construct a transaction from a list of instructions
    async fn construct_tx<S: Signers>(
        &self,
        keyring_instructions: &[Instruction],
        signing_keypairs: &S,
    ) -> Result<Transaction, KeyringError> {
        let mut instructions = vec![];
        let payer_key = self.payer.pubkey();
        let fee_payer = Some(&payer_key);

        instructions.extend_from_slice(keyring_instructions);

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

    /// Process a transaction from a list of instructions
    pub async fn process_ixs<S: Signers>(
        &self,
        keyring_instructions: &[Instruction],
        signing_keypairs: &S,
    ) -> Result<(), KeyringError> {
        let transaction = self
            .construct_tx(keyring_instructions, signing_keypairs)
            .await?;

        self.client
            .send_transaction(&transaction)
            .await
            .map_err(KeyringError::Client)?;

        Ok(())
    }

    /// Create a new keyring
    pub async fn create_keyring(&self, authority: &Keypair) -> Result<(), KeyringError> {
        self.process_ixs(
            &[spl_keyring_program::instruction::create_keyring(
                &spl_keyring_program::id(),
                &authority.pubkey(),
            )?],
            &[authority],
        )
        .await
    }

    /// Add a new key to a keystore
    pub async fn add_entry(
        &self,
        authority: &Keypair,
        entry: EncryptionKeyConfig,
    ) -> Result<(), KeyringError> {
        let mut keystore = self.get_keystore(&authority.pubkey()).await?;
        keystore.0.push(entry.clone());

        let data = keystore
            .try_to_vec()
            .map_err(|e| KeyringError::Program(e.into()))?;

        self.process_ixs(
            &[spl_keyring_program::instruction::update_keyring(
                &spl_keyring_program::id(),
                &authority.pubkey(),
                data,
            )?],
            &[authority],
        )
        .await
    }

    /// Remove a key from a keystore
    pub async fn remove_entry(
        &self,
        authority: &Keypair,
        entry: EncryptionKeyConfig,
    ) -> Result<(), KeyringError> {
        let mut keystore = self.get_keystore(&authority.pubkey()).await?;
        keystore.0.retain(|e| e != &entry);

        let data = keystore
            .try_to_vec()
            .map_err(|e| KeyringError::Program(e.into()))?;

        self.process_ixs(
            &[spl_keyring_program::instruction::update_keyring(
                &spl_keyring_program::id(),
                &authority.pubkey(),
                data,
            )?],
            &[authority],
        )
        .await
    }
}
