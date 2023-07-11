use {
    solana_program_test::{
        processor,
        tokio::{self, sync::Mutex},
        ProgramTest,
    },
    solana_sdk::{
        borsh::get_instance_packed_len,
        instruction::Instruction,
        pubkey::Pubkey,
        rent::Rent,
        signer::{keypair::Keypair, Signer},
        system_instruction,
    },
    spl_keyring_client::{
        keyring::Keyring,
        keystore::{Curve25519, EncryptionKeyConfig, Keystore, Rsa},
    },
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

fn get_fund_rent_instruction(
    keyring: &Keyring<ProgramBanksClientProcessTransaction>,
    authority: &Pubkey,
    new_space: usize,
) -> Instruction {
    let lamports = Rent::default().minimum_balance(new_space);
    system_instruction::transfer(
        authority,
        &keyring.get_keyring_address(authority).0,
        lamports,
    )
}

#[tokio::test]
async fn can_create_keyring() {
    let TestContext { keyring, authority } = TestContext::new().await;

    // Create a keyring
    keyring
        .create_keyring(&authority)
        .await
        .expect("Failed to create keyring");

    // Check to make sure the keyring was created
    let _keyring = keyring
        .get_keystore(&authority.pubkey())
        .await
        .expect("Failed to fetch keyring");
}

#[tokio::test]
async fn can_add_key() {
    let TestContext { keyring, authority } = TestContext::new().await;

    // Create a keyring
    keyring
        .create_keyring(&authority)
        .await
        .expect("Failed to create keyring");

    let new_key = EncryptionKeyConfig::Curve25519(Curve25519(Pubkey::new_unique().to_bytes()));

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &keyring,
                &authority.pubkey(),
                get_instance_packed_len(&new_key).unwrap(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add an entry to the keystore
    keyring
        .add_entry(&authority, new_key.clone())
        .await
        .expect("Failed to add key");

    // Manually grabbing account to check buffer length
    let keyring_account = keyring
        .get_keyring_account(&authority.pubkey())
        .await
        .expect("Failed to fetch keyring account");
    println!("Keystore data length: {}", keyring_account.data.len());

    // Check to make sure the key was added
    let keystore = keyring
        .get_keystore(&authority.pubkey())
        .await
        .expect("Failed to fetch keyring");
    let mock_keystore = Keystore(vec![new_key]);
    assert_eq!(keystore, mock_keystore);
}

#[tokio::test]
async fn can_add_multiple_keys() {
    let TestContext { keyring, authority } = TestContext::new().await;

    // Create a keyring
    keyring
        .create_keyring(&authority)
        .await
        .expect("Failed to create keyring");

    let curve_key = EncryptionKeyConfig::Curve25519(Curve25519(Pubkey::new_unique().to_bytes()));

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &keyring,
                &authority.pubkey(),
                get_instance_packed_len(&curve_key).unwrap(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add an entry to the keystore
    keyring
        .add_entry(&authority, curve_key.clone())
        .await
        .expect("Failed to add key");

    let mut fake_rsa_key_bytes = [0u8; 64];
    fake_rsa_key_bytes
        .copy_from_slice(&[Pubkey::new_unique().as_ref(), Pubkey::new_unique().as_ref()].concat());
    let rsa_key = EncryptionKeyConfig::Rsa(Rsa(fake_rsa_key_bytes));

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &keyring,
                &authority.pubkey(),
                get_instance_packed_len(&rsa_key).unwrap(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add another entry to the keystore
    keyring
        .add_entry(&authority, rsa_key.clone())
        .await
        .expect("Failed to add key");

    // Manually grabbing account to check buffer length
    let keyring_account = keyring
        .get_keyring_account(&authority.pubkey())
        .await
        .expect("Failed to fetch keyring account");
    println!("Keystore data length: {}", keyring_account.data.len());

    // Check to make sure the key was added
    let keystore = keyring
        .get_keystore(&authority.pubkey())
        .await
        .expect("Failed to fetch keyring");
    let mock_keystore = Keystore(vec![curve_key, rsa_key]);
    assert_eq!(keystore, mock_keystore);
}

#[tokio::test]
async fn can_remove_key() {
    let TestContext { keyring, authority } = TestContext::new().await;

    // Create a keyring
    keyring
        .create_keyring(&authority)
        .await
        .expect("Failed to create keyring");

    let curve_key = EncryptionKeyConfig::Curve25519(Curve25519(Pubkey::new_unique().to_bytes()));

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &keyring,
                &authority.pubkey(),
                get_instance_packed_len(&curve_key).unwrap(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add an entry to the keystore
    keyring
        .add_entry(&authority, curve_key.clone())
        .await
        .expect("Failed to add key");

    let mut fake_rsa_key_bytes = [0u8; 64];
    fake_rsa_key_bytes
        .copy_from_slice(&[Pubkey::new_unique().as_ref(), Pubkey::new_unique().as_ref()].concat());
    let rsa_key = EncryptionKeyConfig::Rsa(Rsa(fake_rsa_key_bytes));

    // Fund rent for realloc
    keyring
        .process_ixs(
            &[get_fund_rent_instruction(
                &keyring,
                &authority.pubkey(),
                get_instance_packed_len(&rsa_key).unwrap(),
            )],
            &[&authority],
        )
        .await
        .expect("Failed to fund rent");

    // Add another entry to the keystore
    keyring
        .add_entry(&authority, rsa_key.clone())
        .await
        .expect("Failed to add key");

    // Manually grabbing account to check buffer length
    let keyring_account = keyring
        .get_keyring_account(&authority.pubkey())
        .await
        .expect("Failed to fetch keyring account");
    println!("Added two keys to keystore");
    println!("Keystore data length: {}", keyring_account.data.len());

    // Remove an entry from the keystore
    keyring
        .remove_entry(&authority, curve_key)
        .await
        .expect("Failed to remove key");

    // Manually grabbing account to check buffer length
    let keyring_account = keyring
        .get_keyring_account(&authority.pubkey())
        .await
        .expect("Failed to fetch keyring account");
    println!("Removed Curve25519 key from keystore");
    println!("Keystore data length: {}", keyring_account.data.len());

    // Check to make sure the key was added
    let keystore = keyring
        .get_keystore(&authority.pubkey())
        .await
        .expect("Failed to fetch keyring");
    let mock_keystore = Keystore(vec![rsa_key]);
    assert_eq!(keystore, mock_keystore);
}
