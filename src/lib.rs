#![no_std]

use micro_ecc_sys as uecc;

static mut INITIALIZED: bool = false;

pub fn init() {
    unsafe { uecc::uECC_set_rng(Some(fake_rng)) };
    unsafe { INITIALIZED = true; }
}

#[derive(Copy,Clone,Debug)]
pub struct Error;

// impl core::fmt::Display for Error {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         f.write_str("nisty error")
//     }
// }

pub type Result<T> = core::result::Result<T, Error>;

// enum Curves {
//     NistP256,
//     NistP384,
// }

extern "C" fn fake_rng(dest: *mut u8, size: u32) -> i32 {
    let buf = unsafe { core::slice::from_raw_parts_mut(dest, size as usize) } ;
    for entry in buf {
        *entry = 1;
    }
    1
}

/// the length of a SHA256 digest
pub const SHA256_LENGTH: usize = 64;
/// the length of a public key when serialized
pub const PUBLICKEY_SERIALIZED_LENGTH: usize = 64;
/// the length of a secret key when serialized
pub const SECRETKEY_SERIALIZED_LENGTH: usize = 32;
/// the length of a signature when serialized
pub const SIGNATURE_SERIALIZED_LENGTH: usize = 64;

#[derive(Copy,Clone,Debug,PartialEq)]
pub struct SecretKey(pub [u8; SECRETKEY_SERIALIZED_LENGTH]);

#[derive(Copy,Clone/*,Debug,PartialEq*/)]
pub struct PublicKey(pub [u8; PUBLICKEY_SERIALIZED_LENGTH]);

#[derive(Copy,Clone/*,Debug,PartialEq*/)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

#[derive(Copy,Clone/*,Debug*/)]
pub struct Signature(pub [u8; SIGNATURE_SERIALIZED_LENGTH]);

impl core::cmp::PartialEq<Signature> for Signature {
    fn eq(&self, other: &Self) -> bool {
        for (l, r) in self.0.iter().zip(other.0.iter()) {
            if l != r { return false; }
        }
        true
    }
}

impl Keypair {
    /// NB: need to set RNG first
    pub fn try_generate() -> Result<Self> {
        debug_assert!(unsafe { INITIALIZED } );
        let p256 = unsafe { uecc::uECC_secp256r1() };
        let mut keypair = Self { secret: SecretKey([0u8; 32]), public: PublicKey([0u8; 64]) };
        let return_code = unsafe {
            uecc::uECC_make_key(
                &mut keypair.secret.0[0] as *mut u8,
                &mut keypair.public.0[0] as *mut u8,
                p256,
            )
        };
        if return_code == 1 {
            Ok(keypair)
        } else {
            Err(Error)
        }
    }

    pub fn try_sign_prehashed(&self, prehashed_message: &[u8; SHA256_LENGTH]) -> Result<Signature> {
        debug_assert!(unsafe { INITIALIZED } );
        let p256 = unsafe { uecc::uECC_secp256r1() };
        let mut signature = Signature([0u8; SIGNATURE_SERIALIZED_LENGTH]);
        let return_code = unsafe {
            // TODO: use uECC_sign_deterministic appropriately
            uecc::uECC_sign(
                &self.secret.0[0] as *const u8,
                prehashed_message as *const u8,
                prehashed_message.len() as u32,
                &mut signature.0[0] as *mut u8,
                p256,
            )
        };
        if return_code == 1 {
            Ok(signature)
        } else {
            Err(Error)
        }
    }
}

