//! Types for managing the nested TLV structure of the keystore entry data

use borsh::{BorshDeserialize, BorshSerialize};

/// A keystore
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct Keystore(pub Vec<EncryptionKeyConfig>);

/// An enum for defining recognized encryption algorithms
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub enum EncryptionKeyConfig {
    /// Curve25519 encryption algorithm
    Curve25519(Curve25519),
    /// RSA encryption algorithm
    Rsa(Rsa),
    /// ComplexAlgorithm encryption algorithm (example)
    ComplexAlgorithm(ComplexAlgorithm),
}

/// Curve25519 encryption algorithm
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct Curve25519(pub [u8; 32]);

/// RSA encryption algorithm
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct Rsa(pub [u8; 64]);

/// ComplexAlgorithm encryption algorithm (example)
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct ComplexAlgorithm {
    /// The key itself
    pub key: [u8; 32],
    /// The nonce used for encryption
    pub nonce: [u8; 12],
    /// The associated data used for encryption
    pub aad: [u8; 12],
}
