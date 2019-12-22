#![no_std]

use micro_ecc_sys as uecc;

pub mod rng;

#[allow(unused_imports)]
use cortex_m_semihosting::{dbg, hprintln};

static mut INITIALIZED: bool = false;

// pub fn init() {
//     unsafe { uecc::uECC_set_rng(Some(fake_rng)) };
//     unsafe { INITIALIZED = true; }

//     // // experiment
//     // let key = [0u8; 32];
//     // let nonce = [0u8; 12];
//     // use chacha20::stream_cipher::NewStreamCipher;
//     // let cipher = chacha20::ChaCha20::new_var(&key, &nonce);
// }

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

static mut RNG: Option<rng::ChaCha20Rng> = None;

extern "C" fn chacha_rng(dest: *mut u8, size: u32) -> i32 {
    let buf = unsafe { core::slice::from_raw_parts_mut(dest, size as usize) } ;
    let rng_ref_option = unsafe { RNG.as_mut() };
    if rng_ref_option.is_none() {
        0
    } else {
        let rng_ref = rng_ref_option.unwrap();
        rng_ref.fill(buf);
        1
    }
}

/// the length of a SHA256 digest
pub const SHA256_LENGTH: usize = 32;
/// the length of a public key when serialized
pub const PUBLICKEY_LENGTH: usize = 64;
/// the length of a public key when serialized in compressed format
pub const PUBLICKEY_COMPRESSED_LENGTH: usize = 33;
/// the length of a secret key when serialized
pub const SECRETKEY_LENGTH: usize = 32;
/// the length of a signature when serialized
pub const SIGNATURE_LENGTH: usize = 64;

#[derive(Copy,Clone,Debug,PartialEq)]
pub struct SecretKey(pub [u8; SECRETKEY_LENGTH]);

#[derive(Copy,Clone/*,Debug,PartialEq*/)]
pub struct PublicKey(pub [u8; PUBLICKEY_LENGTH]);

#[derive(Copy,Clone/*,Debug,PartialEq*/)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

#[derive(Copy,Clone/*,Debug*/)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

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

    pub fn try_generate_from(seed: &[u8; SECRETKEY_LENGTH]) -> Result<Self> {

        let p256 = unsafe { uecc::uECC_secp256r1() };
        let mut keypair = Self { secret: SecretKey([0u8; 32]), public: PublicKey([0u8; 64]) };

        // morally, seed can be used as "the" secret key.
        // however, there are corner cases.
        // we'd like to use the seed, if possible, and if not, require no further entropy.
        // idea: give uECC a random number generator that:
        // - starts with the given seed
        // - on future calls, returns ChaCha20 CSRNG outputs from given seed
        // note the probability of  actually ending up in the not-using-seed case:
        // "this is an utterly improbable occurrence" <-- T. Pornin in RFC 6979
        // so all this is an elaborate backup plan...

        let rng = rng::ChaCha20Rng::new(seed);
        unsafe { RNG.replace(rng) };
        unsafe { uecc::uECC_set_rng(Some(chacha_rng)) };

        let return_code = unsafe {
            uecc::uECC_make_key(
                &mut keypair.public.0[0] as *mut u8,
                &mut keypair.secret.0[0] as *mut u8,
                p256,
            )
        };

        // clean up our temporary RNG again
        unsafe { uecc::uECC_set_rng(None) };
        unsafe { RNG.take() };

        if return_code == 1 {
            Ok(keypair)
        } else {
            Err(Error)
        }
    }

    // pub fn try_sign_prehashed(&self, prehashed_message: &[u8; SHA256_LENGTH]) -> Result<Signature> {
    pub fn try_sign_prehashed(&self, prehashed_message: &[u8]) -> Result<Signature> {
        debug_assert!(unsafe { INITIALIZED } );
        debug_assert!(prehashed_message.len() == SHA256_LENGTH);
        let p256 = unsafe { uecc::uECC_secp256r1() };
        let mut signature = Signature([0u8; SIGNATURE_LENGTH]);
        let return_code = unsafe {
            // TODO: use uECC_sign_deterministic appropriately
            uecc::uECC_sign(
                &self.secret.0[0] as *const u8,
                //prehashed_message as *const u8,
                prehashed_message.as_ptr(),
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

    // pub fn try_sign_prehashed(&self, prehashed_message: &[u8; SHA256_LENGTH]) -> Result<Signature> {
    pub fn sign_prehashed_deterministic(&self, prehashed_message: &[u8]) -> Signature {
        debug_assert!(prehashed_message.len() == SHA256_LENGTH);
        let p256 = unsafe { uecc::uECC_secp256r1() };
        let mut signature = Signature([0u8; SIGNATURE_LENGTH]);
        let mut tmp = [0u8; 128];
		let hash_context = uecc::uECC_HashContext {
            init_hash: Some(uecc_init_hash),
            update_hash: Some(uecc_update_hash),
            finish_hash: Some(uecc_finish_hash),
            block_size: 64,
            result_size: 32,
            tmp: &mut tmp[0],// as *mut u8,
		};
        use sha2::digest::Digest;
        #[allow(unused_variables)]
        let sha_context = ShaHashContext {
            context: hash_context,
            sha: sha2::Sha256::new(),
        };
        debug_assert!(unsafe { uecc::uECC_get_rng() }.is_none());
        // unsafe { uecc::uECC_set_rng(None) };  // <-- shouldn't be set here anymore anyway
        let return_code = unsafe {
            // TODO: use uECC_sign_deterministic appropriately
            uecc::uECC_sign_deterministic(
                &self.secret.0[0], // as *const u8,
                &prehashed_message[0],
                prehashed_message.len() as u32,
                &hash_context,
                &mut signature.0[0], // as *mut u8,
                p256,
            )
        };
        assert_eq!(return_code, 1);
        signature
    }
}

impl PublicKey {
    pub fn verify(&self, prehashed_message: &[u8], signature: &Signature) -> bool {
        let p256 = unsafe { uecc::uECC_secp256r1() };
        let return_code = unsafe {
            uecc::uECC_verify(
                &self.0[0], // as *const u8,
                &prehashed_message[0],
                prehashed_message.len() as u32,
                &signature.0[0], // as *const u8,
                p256,
            )
        };
        return_code == 1
    }

    pub fn compress(&self) -> [u8; PUBLICKEY_COMPRESSED_LENGTH] {
        let mut compressed = [0u8; PUBLICKEY_COMPRESSED_LENGTH];
        let p256 = unsafe { uecc::uECC_secp256r1() };
        unsafe {
            uecc::uECC_compress(
                &self.0[0], // as *const u8,
                &mut compressed[0],
                p256,
            )
        };
        compressed
    }
}

#[repr(C)]
struct ShaHashContext {
    context: uecc::uECC_HashContext,
    sha: sha2::Sha256,
}

extern "C" fn uecc_init_hash(context: *const uecc::uECC_HashContext) {
    // dbg!("init hash");
    let sha2 = unsafe { &mut(*(context as *mut ShaHashContext)).sha };
    use sha2::digest::Reset;
    sha2.reset();
}

extern "C" fn uecc_update_hash(context: *const uecc::uECC_HashContext, message: *const u8, message_size: u32) {
    // dbg!("update hash");
    let sha2 = unsafe { &mut(*(context as *mut ShaHashContext)).sha };
    let buf = unsafe { core::slice::from_raw_parts(message, message_size as usize) } ;
    use sha2::digest::Input;
    sha2.input(&buf);
}

pub static mut HASHES: u32 = 0;

pub fn hash_calls() -> u32 {
    unsafe { HASHES }
}

extern "C" fn uecc_finish_hash(context: *const uecc::uECC_HashContext, hash_result: *mut u8) {
    // dbg!("finish hash");
    let sha2 = unsafe { &mut(*(context as *mut ShaHashContext)).sha };
    use sha2::digest::Digest;
    let data = sha2.result_reset();
    let result = unsafe { core::slice::from_raw_parts_mut(hash_result, SHA256_LENGTH) } ;
    result.copy_from_slice(&data);
    // hprintln!("finish hash copied {:?}", result).ok();
    unsafe { HASHES += 1 };
}

