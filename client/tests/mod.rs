use {
    solana_program_test::{
        processor,
        tokio::{self, sync::Mutex},
        ProgramTest,
    },
    solana_sdk::{
        instruction::Instruction,
        pubkey::Pubkey,
        rent::Rent,
        signer::{keypair::Keypair, Signer},
        system_instruction,
    },
    spl_keyring_client::{
        algorithm::{Curve25519, EncryptionAlgorithm, Rsa},
        keyring::Keyring,
    },
    spl_keyring_program::state::Keystore,
    spl_token_client::client::{
        ProgramBanksClient, ProgramBanksClientProcessTransaction, ProgramClient,
    },
    std::sync::Arc,
};

struct TestContext {
    pub keyring: Keyring<ProgramBanksClientProcessTransaction>,
    pub authority: Keypair,
}

impl TestContext {
    async fn new() -> Self {
        let program_test = ProgramTest::new(
            "spl_keyring_program",
            spl_keyring_program::id(),
            processor!(spl_keyring_program::processor::process),
        );
        let ctx = program_test.start_with_context().await;
        let ctx = Arc::new(Mutex::new(ctx));

        let authority = keypair_clone(&ctx.lock().await.payer);

        let client: Arc<dyn ProgramClient<ProgramBanksClientProcessTransaction>> =
            Arc::new(ProgramBanksClient::new_from_context(
                Arc::clone(&ctx),
                ProgramBanksClientProcessTransaction,
            ));

        let keyring = Keyring::new(
            Arc::clone(&client),
            &spl_keyring_program::id(),
            Arc::new(keypair_clone(&authority)),
        );

        Self { keyring, authority }
    }
}

fn keypair_clone(kp: &Keypair) -> Keypair {
    Keypair::from_bytes(&kp.to_bytes()).expect("failed to copy keypair")
}

fn get_fund_rent_instruction(authority: &Pubkey, new_space: usize) -> Instruction {
    let lamports = Rent::default().minimum_balance(new_space);
    system_instruction::transfer(
        authority,
        &Keystore::pda(&spl_keyring_program::id(), authority).0,
        lamports,
    )
}

#[tokio::test]
async fn can_create_keystore() {
    let TestContext { keyring, authority } = TestContext::new().await;

    // Create a keystore
    keyring
        .create_keystore(&authority)
        .await
        .expect("Failed to create keystore");

    // Check to make sure the keystore was created
    let _keystore = keyring
        .get_keystore(&authority.pubkey())
        .await
        .expect("Failed to fetch keystore");
}

#[tokio::test]
async fn can_add_key() {
    let TestContext { keyring, authority } = TestContext::new().await;

    // Create a keystore
    keyring
        .create_keystore(&authority)
        .await
        .expect("Failed to create keystore");

    let new_key = Curve25519::new(Pubkey::new_unique().to_bytes());
    let add_entry_data = new_key.to_keystore_entry();

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &authority.pubkey(),
                add_entry_data.data_len(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add an entry to the keystore
    keyring
        .add_entry(&authority, add_entry_data.clone())
        .await
        .expect("Failed to add key");

    // Manually grabbing account to check buffer length
    let keystore_account = keyring
        .get_keystore_account(&authority.pubkey())
        .await
        .expect("Failed to fetch keystore account");
    println!("Keystore data length: {}", keystore_account.data.len());

    // Check to make sure the key was added
    let keystore = keyring
        .get_keystore(&authority.pubkey())
        .await
        .expect("Failed to fetch keystore");
    let mock_keystore = Keystore {
        entries: vec![add_entry_data],
    };
    assert_eq!(keystore, mock_keystore);
}

#[tokio::test]
async fn can_add_multiple_keys() {
    let TestContext { keyring, authority } = TestContext::new().await;

    // Create a keystore
    keyring
        .create_keystore(&authority)
        .await
        .expect("Failed to create keystore");

    let curve_key = Curve25519::new(Pubkey::new_unique().to_bytes());
    let curve_entry_data = curve_key.to_keystore_entry();

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &authority.pubkey(),
                curve_entry_data.data_len(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add an entry to the keystore
    keyring
        .add_entry(&authority, curve_entry_data.clone())
        .await
        .expect("Failed to add key");

    let mut fake_rsa_key_bytes = [0u8; 64];
    fake_rsa_key_bytes
        .copy_from_slice(&[Pubkey::new_unique().as_ref(), Pubkey::new_unique().as_ref()].concat());
    let rsa_key = Rsa::new(fake_rsa_key_bytes);
    let rsa_entry_data = rsa_key.to_keystore_entry();

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &authority.pubkey(),
                rsa_entry_data.data_len(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add another entry to the keystore
    keyring
        .add_entry(&authority, rsa_entry_data.clone())
        .await
        .expect("Failed to add key");

    // Manually grabbing account to check buffer length
    let keystore_account = keyring
        .get_keystore_account(&authority.pubkey())
        .await
        .expect("Failed to fetch keystore account");
    println!("Keystore data length: {}", keystore_account.data.len());

    // Check to make sure the key was added
    let keystore = keyring
        .get_keystore(&authority.pubkey())
        .await
        .expect("Failed to fetch keystore");
    let mock_keystore = Keystore {
        entries: vec![curve_entry_data, rsa_entry_data],
    };
    assert_eq!(keystore, mock_keystore);
}

#[tokio::test]
async fn can_remove_key() {
    let TestContext { keyring, authority } = TestContext::new().await;

    // Create a keystore
    keyring
        .create_keystore(&authority)
        .await
        .expect("Failed to create keystore");

    let curve_key = Curve25519::new(Pubkey::new_unique().to_bytes());
    let curve_entry_data = curve_key.to_keystore_entry();

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &authority.pubkey(),
                curve_entry_data.data_len(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add an entry to the keystore
    keyring
        .add_entry(&authority, curve_entry_data.clone())
        .await
        .expect("Failed to add key");

    let mut fake_rsa_key_bytes = [0u8; 64];
    fake_rsa_key_bytes
        .copy_from_slice(&[Pubkey::new_unique().as_ref(), Pubkey::new_unique().as_ref()].concat());
    let rsa_key = Rsa::new(fake_rsa_key_bytes);
    let rsa_entry_data = rsa_key.to_keystore_entry();

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &authority.pubkey(),
                rsa_entry_data.data_len(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add another entry to the keystore
    keyring
        .add_entry(&authority, rsa_entry_data.clone())
        .await
        .expect("Failed to add key");

    // Manually grabbing account to check buffer length
    let keystore_account = keyring
        .get_keystore_account(&authority.pubkey())
        .await
        .expect("Failed to fetch keystore account");
    println!("Added two keys to keystore");
    println!("Keystore data length: {}", keystore_account.data.len());

    // Remove an entry from the keystore
    keyring
        .remove_entry(&authority, curve_entry_data)
        .await
        .expect("Failed to remove key");

    // Manually grabbing account to check buffer length
    let keystore_account = keyring
        .get_keystore_account(&authority.pubkey())
        .await
        .expect("Failed to fetch keystore account");
    println!("Removed Curve25519 key from keystore");
    println!("Keystore data length: {}", keystore_account.data.len());

    // Check to make sure the key was added
    let keystore = keyring
        .get_keystore(&authority.pubkey())
        .await
        .expect("Failed to fetch keystore");
    let mock_keystore = Keystore {
        entries: vec![rsa_entry_data],
    };
    assert_eq!(keystore, mock_keystore);
}
