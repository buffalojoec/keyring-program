#![cfg(feature = "test-sbf")]

use {
    solana_program_test::{processor, tokio::sync::Mutex, ProgramTest, ProgramTestContext},
    solana_sdk::{
        pubkey::Pubkey, signature::Signer, signer::keypair::Keypair, system_instruction,
        transaction::Transaction,
    },
    spl_keyring::instruction::{add_entry, create_keystore, remove_entry},
    spl_keyring_client::{
        client::{
            ProgramBanksClient, ProgramBanksClientProcessTransaction, ProgramClient,
            SendTransaction,
        },
        token::Token,
    },
    spl_keyring_program::state::Keystore,
    std::{assert_eq, sync::Arc},
};

pub async fn setup(
    program_id: &Pubkey,
) -> (
    Arc<Mutex<ProgramTestContext>>,
    Arc<dyn ProgramClient<ProgramBanksClientProcessTransaction>>,
    Arc<Keypair>,
) {
    let mut program_test = ProgramTest::new(
        "spl_keyring",
        *program_id,
        processor!(spl_keyring::processor::process),
    );
    program_test.prefer_bpf(false);

    let context = program_test.start_with_context().await;
    let payer =
        Arc::new(Keypair::from_bytes(&context.payer.to_bytes()).expect("failed to copy keypair"));
    let context = Arc::new(Mutex::new(context));

    let client: Arc<dyn ProgramClient<ProgramBanksClientProcessTransaction>> =
        Arc::new(ProgramBanksClient::new_from_context(
            Arc::clone(&context),
            ProgramBanksClientProcessTransaction,
        ));
    (context, client, payer)
}

#[tokio::test]
async fn test_create_keystore() {
    let program_id = Pubkey::new_unique();
    let (context, client, payer) = setup(&program_id).await;

    let transaction = Transaction::new_signed_with_payer(
        &[create_keystore(&program_id, &payer.pubkey())],
        Some(&payer.pubkey()),
        &[&payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    let fetched_keystore_account = context
        .banks_client
        .get_account(Keystore::pda(&program_id, &payer.pubkey()).0)
        .await
        .unwrap()
        .unwrap();
    assert!(fetched_keystore_account.lamports != 0);
}

#[tokio::test]
async fn test_add_entry() {
    let program_id = Pubkey::new_unique();
    let (context, client, payer) = setup(&program_id).await;

    let entry_curve25519 = Curve25519::new(); // TODO
    let entry_rsa = Rsa::new(); // TODO

    let transaction = Transaction::new_signed_with_payer(
        &[
            create_keystore(&program_id, &payer.pubkey()),
            add_entry(
                &program_id,
                &payer.pubkey(),
                entry_curve25519.clone().to_bytes(),
            ),
            add_entry(&program_id, &payer.pubkey(), entry_rsa.clone().to_bytes()),
        ],
        Some(&payer.pubkey()),
        &[&payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    let fetched_keystore_account = context
        .banks_client
        .get_account(Keystore::pda(&program_id, &payer.pubkey()).0)
        .await
        .unwrap()
        .unwrap();
    let keystore = Keystore::unpack(fetched_keystore_account.try_borrow_data().unwrap()).unwrap();

    let mock_keystore = Keystore {
        entries: vec![entry_curve25519, entry_rsa],
    };
    assert_eq!(keystore, mock_keystore);
}

#[tokio::test]
async fn test_remove_entry() {
    let program_id = Pubkey::new_unique();
    let (context, client, payer) = setup(&program_id).await;

    let entry_curve25519 = Curve25519::new(); // TODO
    let entry_rsa = Rsa::new(); // TODO

    let transaction = Transaction::new_signed_with_payer(
        &[
            create_keystore(&program_id, &payer.pubkey()),
            add_entry(
                &program_id,
                &payer.pubkey(),
                entry_curve25519.clone().to_bytes(),
            ),
            add_entry(&program_id, &payer.pubkey(), entry_rsa.clone().to_bytes()),
            remove_entry(
                &program_id,
                &payer.pubkey(),
                entry_curve25519.clone().to_bytes(),
            ),
        ],
        Some(&payer.pubkey()),
        &[&payer],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    let fetched_keystore_account = context
        .banks_client
        .get_account(Keystore::pda(&program_id, &payer.pubkey()).0)
        .await
        .unwrap()
        .unwrap();
    let keystore = Keystore::unpack(fetched_keystore_account.try_borrow_data().unwrap()).unwrap();

    let mock_keystore = Keystore {
        entries: vec![entry_rsa],
    };
    assert_eq!(keystore, mock_keystore);
}
