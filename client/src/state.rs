//! State representations of recognized encryption algorithms

use spl_discriminator::SplDiscriminate;

/// A trait for defining recognized encryption algorithms
pub trait EncryptionAlgorithm: SplDiscriminate {
    /// The length of the encryption key in bytes
    const KEY_LENGTH: usize;
    /// Any required configurations for this encprytion algorithm
    type Configurations: SplDiscriminate;
}

/// Struct representing "no configurations" required for a particular encryption
/// algorithm
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("configurations:none")]
pub struct NoConfigurations;

/// Curve25519 encryption algorithm
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("key:curve25519")]
pub struct Curve25519;

impl EncryptionAlgorithm for Curve25519 {
    const KEY_LENGTH: usize = 32;
    type Configurations = NoConfigurations;
}

/// X25519 encryption algorithm
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("key:x25519")]
pub struct X25519;

impl EncryptionAlgorithm for X25519 {
    const KEY_LENGTH: usize = 32;
    type Configurations = NoConfigurations;
}

/// Ed25519 encryption algorithm
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("key:ed25519")]
pub struct Ed25519;

impl EncryptionAlgorithm for Ed25519 {
    const KEY_LENGTH: usize = 32;
    type Configurations = NoConfigurations;
}

/// Cha-Cha20-Poly1305 encryption algorithm
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("key:cha-cha20-poly1305")]
pub struct ChaCha20Poly1305;

impl EncryptionAlgorithm for ChaCha20Poly1305 {
    const KEY_LENGTH: usize = 32;
    type Configurations = ChaCha20Poly1305Configurations;
}

/// Cha-Cha20-Poly1305 configurations
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("configurations:cha-cha20-poly1305")]
pub struct ChaCha20Poly1305Configurations {
    /// The nonce used for encryption
    pub nonce: [u8; 12],
    /// The associated data used for encryption
    pub aad: [u8; 12],
}
