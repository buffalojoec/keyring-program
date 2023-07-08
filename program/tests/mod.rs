#![cfg(feature = "test-sbf")]

use {
    solana_program_test::{
        processor,
        tokio::{self, sync::Mutex},
        ProgramTest, ProgramTestContext,
    },
    solana_sdk::{
        instruction::Instruction, pubkey::Pubkey, rent::Rent, signature::Signer,
        signer::keypair::Keypair, system_instruction, transaction::Transaction,
    },
    spl_keyring_client::algorithm::{Curve25519, EncryptionAlgorithm, Rsa},
    spl_keyring_program::{
        id,
        instruction::{add_entry, create_keystore, remove_entry},
        state::Keystore,
    },
    std::{assert_eq, sync::Arc},
};

fn get_fund_rent_instruction(
    program_id: &Pubkey,
    authority: &Pubkey,
    new_space: usize,
) -> Instruction {
    let lamports = Rent::default().minimum_balance(new_space);
    system_instruction::transfer(authority, &Keystore::pda(program_id, authority).0, lamports)
}

#[tokio::test]
async fn test_create_keystore() {
    let program_id = id();
    let mut pt = ProgramTest::new(
        "spl_keyring_program",
        program_id,
        processor!(spl_keyring_program::processor::process),
    );
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let transaction = Transaction::new_signed_with_payer(
        &[create_keystore(&program_id, &payer.pubkey()).unwrap()],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(transaction).await.unwrap();

    let fetched_keystore_account = banks_client
        .get_account(Keystore::pda(&program_id, &payer.pubkey()).0)
        .await
        .unwrap()
        .unwrap();
    assert!(fetched_keystore_account.lamports != 0);
}

#[tokio::test]
async fn test_add_entry() {
    let program_id = id();
    let mut pt = ProgramTest::new(
        "spl_keyring_program",
        program_id,
        processor!(spl_keyring_program::processor::process),
    );
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let curve_key = Curve25519::new(Pubkey::new_unique().to_bytes());
    let curve_entry_data = curve_key.to_keystore_entry();

    let mut fake_rsa_key_bytes = [0u8; 64];
    fake_rsa_key_bytes
        .copy_from_slice(&[Pubkey::new_unique().as_ref(), Pubkey::new_unique().as_ref()].concat());
    let rsa_key = Rsa::new(fake_rsa_key_bytes);
    let rsa_entry_data = rsa_key.to_keystore_entry();

    let transaction = Transaction::new_signed_with_payer(
        &[
            create_keystore(&program_id, &payer.pubkey()).unwrap(),
            get_fund_rent_instruction(&program_id, &payer.pubkey(), curve_entry_data.data_len()),
            add_entry(
                &program_id,
                &payer.pubkey(),
                curve_entry_data.clone().pack().unwrap(),
            )
            .unwrap(),
            get_fund_rent_instruction(&program_id, &payer.pubkey(), rsa_entry_data.data_len()),
            add_entry(
                &program_id,
                &payer.pubkey(),
                rsa_entry_data.clone().pack().unwrap(),
            )
            .unwrap(),
        ],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(transaction).await.unwrap();

    let fetched_keystore_account = banks_client
        .get_account(Keystore::pda(&program_id, &payer.pubkey()).0)
        .await
        .unwrap()
        .unwrap();
    let keystore = Keystore::unpack(&fetched_keystore_account.data).unwrap();
    let mock_keystore = Keystore {
        entries: vec![curve_entry_data, rsa_entry_data],
    };
    assert_eq!(keystore, mock_keystore);
}

#[tokio::test]
async fn test_remove_entry() {
    let program_id = id();
    let mut pt = ProgramTest::new(
        "spl_keyring_program",
        program_id,
        processor!(spl_keyring_program::processor::process),
    );
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let curve_key = Curve25519::new(Pubkey::new_unique().to_bytes());
    let curve_entry_data = curve_key.to_keystore_entry();

    let mut fake_rsa_key_bytes = [0u8; 64];
    fake_rsa_key_bytes
        .copy_from_slice(&[Pubkey::new_unique().as_ref(), Pubkey::new_unique().as_ref()].concat());
    let rsa_key = Rsa::new(fake_rsa_key_bytes);
    let rsa_entry_data = rsa_key.to_keystore_entry();

    let transaction = Transaction::new_signed_with_payer(
        &[
            create_keystore(&program_id, &payer.pubkey()).unwrap(),
            get_fund_rent_instruction(&program_id, &payer.pubkey(), curve_entry_data.data_len()),
            add_entry(
                &program_id,
                &payer.pubkey(),
                curve_entry_data.clone().pack().unwrap(),
            )
            .unwrap(),
            get_fund_rent_instruction(&program_id, &payer.pubkey(), rsa_entry_data.data_len()),
            add_entry(
                &program_id,
                &payer.pubkey(),
                rsa_entry_data.clone().pack().unwrap(),
            )
            .unwrap(),
            remove_entry(
                &program_id,
                &payer.pubkey(),
                curve_entry_data.clone().pack().unwrap(),
            )
            .unwrap(),
        ],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks_client.process_transaction(transaction).await.unwrap();

    let fetched_keystore_account = banks_client
        .get_account(Keystore::pda(&program_id, &payer.pubkey()).0)
        .await
        .unwrap()
        .unwrap();
    let keystore = Keystore::unpack(&fetched_keystore_account.data).unwrap();
    let mock_keystore = Keystore {
        entries: vec![rsa_entry_data],
    };
    assert_eq!(keystore, mock_keystore);
}
