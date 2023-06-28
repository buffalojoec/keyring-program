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
#[discriminator_hash_input("spl_keyring_program:key:Curve25519")]
pub struct Curve25519 {
    key: [u8; Self::KEY_LENGTH],
}
impl Curve25519 {
    /// Create a new instance of Curve25519
    pub fn new(key: [u8; Self::KEY_LENGTH]) -> Self {
        Self { key }
    }
}

impl EncryptionAlgorithm for Curve25519 {
    const KEY_LENGTH: usize = 32;
    type Configurations = NoConfigurations;
}

/// RSA encryption algorithm
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:key:RSA")]
pub struct RSA {
    key: [u8; Self::KEY_LENGTH],
}
impl RSA {
    /// Create a new instance of RSA
    pub fn new(key: [u8; Self::KEY_LENGTH]) -> Self {
        Self { key }
    }
}

impl EncryptionAlgorithm for RSA {
    const KEY_LENGTH: usize = 32;
    type Configurations = NoConfigurations;
}

/// ComplexAlgorithm encryption algorithm
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:key:ComplexAlgorithm")]
pub struct ComplexAlgorithm {
    key: [u8; Self::KEY_LENGTH],
}
impl ComplexAlgorithm {
    /// Create a new instance of ComplexAlgorithm
    pub fn new(key: [u8; Self::KEY_LENGTH]) -> Self {
        Self { key }
    }
}

impl EncryptionAlgorithm for ComplexAlgorithm {
    const KEY_LENGTH: usize = 32;
    type Configurations = ComplexAlgorithmConfigurations;
}

/// ComplexAlgorithm configurations
#[derive(Clone, Debug, Default, PartialEq, SplDiscriminate)]
#[discriminator_hash_input("spl_keyring_program:configuration:ComplexAlgorithm")]
pub struct ComplexAlgorithmConfigurations {
    /// The nonce used for encryption
    pub nonce: [u8; 12],
    /// The additional authenticated data
    pub aad: [u8; 12],
}
