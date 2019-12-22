#![no_std]
/*! Library for NIST P256 signatures, for when you really need them.

This library completely decouples entropy from key generation and signatures,
and offers a similar API as [salty][salty].

In particular, all signatures are *deterministic*, similar to [RFC 6979][rfc-6979].

The flip side of this is that we need to pull in a CSRNG, for the ultra-rare
case where a 32-byte seed does not directly give rise to a valid keypair; we use ChaCha20.
Likely, we could get by with just repeatedly hashing the seed if necessary.

In the backend, this library currently uses [micro-ecc][micro-ecc], exposed via
[micro-ecc-sys][micro-ecc-sys].

[rfc-6979]: https://tools.ietf.org/html/rfc6979
[salty]: https://crates.io/crates/salty
[micro-ecc]: https://github.com/kmackay/micro-ecc
[micro-ecc-sys]: https://crates.io/crates/micro-ecc-sys

## Example
```
let seed = [1u8; 32]; // use an actually entropic seed
let keypair = nisty::Keypair::from(&seed);
let message = b"hello, nisty";
let signature = keypair.sign(message);
assert!(keypair.public.verify(message, &signature));
```

## Microcontrollers
Because `bindgen`, `no_std` and Rust's limited feature tree handling don't play nice
together, on microcontrollers the bindings to `micro-ecc` need to be pre-generated.

For Cortex-M4 and Cortex-M33 microcontrollers, they are packaged, and it is sufficient
to use `nisty` as follows:

```toml
[dependencies.nisty]
default-features = false
```

When compiled as release build, these platforms automatically pick up UMAAL assembly optimizations.

On an NXP LPC55S69, signature generation takes around 6.9M cycles, signature verification around 7.6M.
*/

use micro_ecc_sys as uecc;

mod rng;

/// the length of a SHA256 digest
pub const SHA256_LENGTH: usize = 32;
// use sha2::digest::generic_array::typenum::marker_traits::Unsigned;
// pub const SHA2_LENGTH: usize = <sha2::Sha256 as sha2::digest::FixedOutput>::OutputSize::to_usize();
/// the length of a public key when serialized
pub const PUBLICKEY_LENGTH: usize = 64;
/// the length of a public key when serialized in compressed format
pub const PUBLICKEY_COMPRESSED_LENGTH: usize = 33;
/// the length of a secret key seed when serialized
pub const SEED_LENGTH: usize = 32;
/// the length of a secret key when serialized
pub const SECRETKEY_LENGTH: usize = 32;
/// the length of a signature when serialized
pub const SIGNATURE_LENGTH: usize = 64;

/// Either there is an error, or there is not - no reasons given.
#[derive(Copy,Clone,Debug)]
pub struct Error;

pub type Result<T> = core::result::Result<T, Error>;

/// 32 entropic bytes, input for key generation.
#[derive(Copy,Clone,Debug,PartialEq)]
pub struct Seed([u8; SECRETKEY_LENGTH]);

/// Secret part of a keypair, a scalar.
#[derive(Copy,Clone,Debug,PartialEq)]
pub struct SecretKey(pub [u8; SECRETKEY_LENGTH]);

/// Public part of a keypair, a point on the curve.
#[derive(Copy,Clone/*,Debug,PartialEq*/)]
pub struct PublicKey(pub [u8; PUBLICKEY_LENGTH]);

/// Create keys, generate signatures.
///
/// Key generation from a seed needs no further entropic input.
///
/// Signatures are always deterministic, they need no entropic input.
#[derive(Copy,Clone/*,Debug,PartialEq*/)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// Pair of two curve scalars.
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

/// Convenience function, calculates SHA256 hash digest.
pub fn prehash(message: &[u8]) -> [u8; SHA256_LENGTH] {
    use sha2::digest::Digest;
    let mut hash = sha2::Sha256::new();
    hash.input(message);
    let data = hash.result();
    data.into()
}

impl Keypair {

    fn curve() -> uecc::uECC_Curve {
        unsafe { uecc::uECC_secp256r1() }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        use sha2::digest::Digest;
        let mut hash = sha2::Sha256::new();
        hash.input(message);
        let data = hash.result();
        let mut prehashed_message = [0u8; 32];
        prehashed_message.copy_from_slice(data.as_slice());
        self.sign_prehashed(&prehashed_message)
    }

    // pub fn try_sign_prehashed(&self, prehashed_message: &[u8; SHA256_LENGTH]) -> Result<Signature> {
    pub fn sign_prehashed(&self, prehashed_message: &[u8; SHA256_LENGTH]) -> Signature {
        debug_assert!(prehashed_message.len() == SHA256_LENGTH);
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
                Self::curve(),
            )
        };
        assert_eq!(return_code, 1);
        signature
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.public.verify(message, signature)
    }

    pub fn verify_prehashed(&self, prehashed_message: &[u8; 32], signature: &Signature) -> bool {
        self.public.verify_prehashed(prehashed_message, signature)
    }

}

impl From<&[u8; SEED_LENGTH]> for Keypair {

    fn from(seed: &[u8; SECRETKEY_LENGTH]) -> Self {

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
        unsafe {
            rng::RNG.replace(rng);
            uecc::uECC_set_rng(Some(rng::chacha_rng));
        }

        let return_code = unsafe {
            uecc::uECC_make_key(
                &mut keypair.public.0[0] as *mut u8,
                &mut keypair.secret.0[0] as *mut u8,
                Self::curve(),
            )
        };

        // clean up our temporary RNG again
        unsafe {
            uecc::uECC_set_rng(None);
            rng::RNG.take();
        };

        debug_assert!(return_code == 1);
        keypair
    }
}

// PROBLEM: conflicting implementation
//
// impl core::convert::TryFrom<&[u8; SEED_LENGTH]> for Keypair {
//     type Error = Error;

//     fn try_from(seed: &[u8; SECRETKEY_LENGTH]) -> Result<Self> {

//     (...)

//         // clean up our temporary RNG again
//         unsafe {
//             uecc::uECC_set_rng(None);
//             RNG.take();
//         };

//         if return_code == 1 {
//             Ok(keypair)
//         } else {
//             Err(Error)
//         }
//     }
// }


impl PublicKey {
    pub fn verify_prehashed(&self, prehashed_message: &[u8; 32], signature: &Signature) -> bool {
        let return_code = unsafe {
            uecc::uECC_verify(
                &self.0[0], // as *const u8,
                &prehashed_message[0],
                prehashed_message.len() as u32,
                &signature.0[0], // as *const u8,
                Keypair::curve(),
            )
        };
        return_code == 1
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let prehashed_message = prehash(message);
        self.verify_prehashed(&prehashed_message, signature)
    }

    pub fn compress(&self) -> [u8; PUBLICKEY_COMPRESSED_LENGTH] {
        let mut compressed = [0u8; PUBLICKEY_COMPRESSED_LENGTH];
        unsafe {
            uecc::uECC_compress(
                &self.0[0], // as *const u8,
                &mut compressed[0],
                Keypair::curve(),
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

static mut HASHES: u32 = 0;

/// How many hash digests were calculated for signatures so far.
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

