#![no_std]
/*! Library for NIST P256 signatures, for when you really need them.

This library completely decouples entropy from key generation and signatures,
and offers a similar API as [salty][salty].

In particular, all signatures are *deterministic*, similar to [RFC 6979][rfc-6979].

Conversions between `Seed`s, `SecretKey`s, `PublicKey`s, `Keypair`s, `Signature`s and their
underlying byte arrays are implemented in terms of the standard `core::convert` traits
`TryFrom`, `From`, `Into`, and a custom trait `AsArrayRef`. For convenience, these
conversions are also exposed as associated functions and methods.

In the backend, this library currently uses [micro-ecc][micro-ecc], exposed via
[micro-ecc-sys][micro-ecc-sys].

[rfc-6979]: https://tools.ietf.org/html/rfc6979
[salty]: https://crates.io/crates/salty
[micro-ecc]: https://github.com/kmackay/micro-ecc
[micro-ecc-sys]: https://crates.io/crates/micro-ecc-sys

## Example
```
let seed = [1u8; 32]; // use an actually entropic seed
let keypair = nisty::Keypair::generate(&seed, 1).unwrap();
let message = b"hello, nisty";
let signature = keypair.sign(message);
assert!(keypair.public.verify(message, signature));

let public_key_bytes: [u8; 64] = keypair.public.to_bytes();
let signature_bytes: [u8; 64] = signature.to_bytes();
assert!(
    nisty::PublicKey::try_from_bytes(public_key_bytes)
        .unwrap()
        .verify(message, &signature_bytes));

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
// use zeroize::Zeroize;

fn nist_p256() -> uecc::uECC_Curve {
    unsafe { uecc::uECC_secp256r1() }
}

/// 32, the length of a SHA256 digest
pub const DIGEST_LENGTH: usize = 32;
/// 64, the length of a public key
pub const PUBLIC_KEY_LENGTH: usize = 64;
// /// 33, the length of a compressed public key
// pub const PUBLIC_KEY_COMPRESSED_LENGTH: usize = 33;
/// 32, the length of a secret key seed
pub const SEED_LENGTH: usize = 32;
/// 32, the length of a secret key
pub const SECRET_KEY_LENGTH: usize = 32;
/// 64, the length of a signature
pub const SIGNATURE_LENGTH: usize = 64;

/// Either there is an error, or there is not - no reasons given.
#[derive(Copy,Clone,Debug)]
pub struct Error;

pub type Result<T> = core::result::Result<T, Error>;

/// Similar to [`core::convert::AsRef`](https://doc.rust-lang.org/core/convert/trait.AsRef.html).
///
/// Advantage: we can implement it on arrays of more than 32 bytes
///
/// Disadvantage: does not auto-dereference
pub trait AsArrayRef<T> where
    T: ?Sized,
{
    fn as_array_ref(&self) -> &T;
}

impl AsArrayRef<[u8; 32]> for [u8; 32] {
    fn as_array_ref(&self) -> &[u8; 32] {
        &self
    }
}

impl AsArrayRef<[u8; 32]> for &[u8; 32] {
    fn as_array_ref(&self) -> &[u8; 32] {
        self
    }
}

impl AsArrayRef<[u8; 64]> for [u8; 64] {
    fn as_array_ref(&self) -> &[u8; 64] {
        &self
    }
}

impl AsArrayRef<[u8; 64]> for &[u8; 64] {
    fn as_array_ref(&self) -> &[u8; 64] {
        self
    }
}

type SeedBytes = [u8; SEED_LENGTH];
/// 32 entropic bytes, input for key generation.
#[derive(Copy,Clone,Debug,PartialEq)]
pub struct Seed(SeedBytes);

impl From<SeedBytes> for Seed {
    fn from(seed_bytes: SeedBytes) -> Seed {
        Seed(seed_bytes)
    }
}

impl Into<SeedBytes> for Seed {
    fn into(self) -> SeedBytes {
        self.0
    }
}

impl AsArrayRef<SeedBytes> for Seed {
    fn as_array_ref(&self) -> &SeedBytes {
        &self.0
    }
}

impl Seed {
    pub fn from_bytes(seed_bytes: SeedBytes) -> Self {
        Self::from(seed_bytes)
    }

    pub fn to_bytes(self) -> SeedBytes {
        self.into()
    }

    pub fn as_bytes(&self) -> &SeedBytes {
        self.as_array_ref()
    }
}

type SecretKeyBytes = [u8; SECRET_KEY_LENGTH];
/// Secret part of a keypair, a scalar.
#[derive(Clone,Debug,PartialEq)]
pub struct SecretKey(SecretKeyBytes);

impl core::convert::TryFrom<SecretKeyBytes> for SecretKey {
    type Error = Error;

    fn try_from(secret_key_bytes: SecretKeyBytes) -> Result<SecretKey> {
        Ok(Keypair::try_from(secret_key_bytes)?.secret)
    }
}

impl Into<SecretKeyBytes> for SecretKey {
    fn into(self) -> SecretKeyBytes {
        self.0
    }
}

impl AsArrayRef<SecretKeyBytes> for SecretKey {
    fn as_array_ref(&self) -> &SecretKeyBytes {
        &self.0
    }
}

impl SecretKey {
    pub fn try_from_bytes(secret_key_bytes: SecretKeyBytes) -> Result<Self> {
        use core::convert::TryFrom;
        Self::try_from(secret_key_bytes)
    }

    pub fn to_bytes(self) -> SecretKeyBytes {
        self.into()
    }

    pub fn as_bytes(&self) -> &SecretKeyBytes {
        self.as_array_ref()
    }
}

type PublicKeyBytes = [u8; PUBLIC_KEY_LENGTH];
/// Public part of a keypair, a point on the curve.
#[derive(Copy,Clone)]
pub struct PublicKey(PublicKeyBytes);

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "PublicKey({:?})", &self.0[..])
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0[..] == other.0[..]
    }
}

impl core::convert::TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Error;

    fn try_from(public_key_bytes: PublicKeyBytes) -> Result<PublicKey> {
        let return_code = unsafe {
            uecc::uECC_valid_public_key(
                &public_key_bytes[0],
                nist_p256(),
            )
        };
        if return_code == 1 {
            Ok(PublicKey(public_key_bytes))
        } else {
            Err(Error)
        }
    }
}

impl Into<PublicKeyBytes> for PublicKey {
    fn into(self) -> PublicKeyBytes {
        self.0
    }
}

impl AsArrayRef<PublicKeyBytes> for PublicKey {
    fn as_array_ref(&self) -> &PublicKeyBytes {
        &self.0
    }
}

impl PublicKey {
     pub fn try_from_bytes(public_key_bytes: PublicKeyBytes) -> Result<Self> {
         use core::convert::TryFrom;
         Self::try_from(public_key_bytes)
     }

    pub fn to_bytes(self) -> PublicKeyBytes {
        self.into()
    }

    pub fn as_bytes(&self) -> &PublicKeyBytes {
        self.as_array_ref()
    }
}

/// Create keys, generate signatures.
///
/// Key generation from a seed needs no further entropic input.
///
/// Signatures are always deterministic, they need no entropic input.
#[derive(Clone,Debug,PartialEq)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

type SignatureBytes = [u8; SIGNATURE_LENGTH];
/// Pair of two curve scalars.
#[derive(Copy,Clone)]
pub struct Signature(SignatureBytes);

impl core::fmt::Debug for Signature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "Signature({:?})", &self.0[..])
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.0[..] == other.0[..]
    }
}

impl From<SignatureBytes> for Signature {
    fn from(signature_bytes: SignatureBytes) -> Signature {
        Signature(signature_bytes)
    }
}

impl Into<SignatureBytes> for Signature {
    fn into(self) -> SignatureBytes {
        self.0
    }
}

impl AsArrayRef<SignatureBytes> for Signature {
    fn as_array_ref(&self) -> &SignatureBytes {
        &self.0
    }
}

impl Signature {
    pub fn from_bytes(signature_bytes: SignatureBytes) -> Self {
        Self::from(signature_bytes)
    }

    pub fn to_bytes(self) -> SignatureBytes {
        self.into()
    }

    pub fn as_bytes(&self) -> &SignatureBytes {
        self.as_array_ref()
    }
}

/// Convenience function, calculates SHA256 hash digest.
pub fn prehash(message: &[u8]) -> [u8; DIGEST_LENGTH] {
    use sha2::digest::Digest;
    let mut hash = sha2::Sha256::new();
    hash.input(message);
    let data = hash.result();
    data.into()
}

impl Keypair {
    /// Generate new public key, based on a seed assumed to be entropic.
    ///
    /// Approach: if the given seed does not correspond to a secret key,
    /// repeatedly its SHA-256 digest is computed, until it does.
    ///
    /// Instead of calling with `tries = 1`, consider using `Keypair::try_from_bytes`.
    pub fn generate(seed: impl AsArrayRef<SeedBytes>, tries: usize) -> Result<Keypair> {
        let mut secret = <[u8; SECRET_KEY_LENGTH]>::from(seed.as_array_ref().clone());

        use core::convert::TryFrom;
        for _attempt in 0..tries {

            let candidate = Keypair::try_from(secret.clone());
            if candidate.is_ok() {
                return candidate;
            }
            secret = prehash(&secret);
        }

        Err(Error)
    }

    /// Return keypair with given bytes as secret key, if valid.
    ///
    /// If uncertain whether the bytes are a valid secret key,
    /// try `Keypair::generate` with `tries > 1` instead.
    pub fn try_from_bytes(secret_key_bytes: &SecretKeyBytes) -> Result<Keypair> {
        use core::convert::TryFrom;
        Keypair::try_from(secret_key_bytes.clone())
    }

    pub fn split(self) -> (SecretKey, PublicKey) {
        (self.secret, self.public)
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

    // pub fn try_sign_prehashed(&self, prehashed_message: &[u8; DIGEST_LENGTH]) -> Result<Signature> {
    pub fn sign_prehashed(&self, prehashed_message: &[u8; DIGEST_LENGTH]) -> Signature {
        debug_assert!(prehashed_message.len() == DIGEST_LENGTH);
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
        // debug_assert!(unsafe { uecc::uECC_get_rng() }.is_none());
        unsafe { uecc::uECC_set_rng(None) };  // <-- shouldn't be set here anymore anyway
        let return_code = unsafe {
            // TODO: use uECC_sign_deterministic appropriately
            uecc::uECC_sign_deterministic(
                &self.secret.0[0], // as *const u8,
                &prehashed_message[0],
                prehashed_message.len() as u32,
                &hash_context,
                &mut signature.0[0], // as *mut u8,
                nist_p256(),
            )
        };
        assert_eq!(return_code, 1);
        signature
    }

    // pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
    pub fn verify(&self, message: &[u8], signature: impl AsArrayRef<SignatureBytes>) -> bool {
        self.public.verify(message, signature)
    }

    // pub fn verify_prehashed(&self, prehashed_message: &[u8; 32], signature: &Signature) -> bool {
    pub fn verify_prehashed(&self, prehashed_message: &[u8; 32], signature: impl AsArrayRef<SignatureBytes>) -> bool {
        self.public.verify_prehashed(prehashed_message, signature)
    }

}

impl core::convert::TryFrom<SecretKeyBytes> for Keypair {

    type Error = Error;

    fn try_from(secret_key_bytes: SecretKeyBytes) -> Result<Self> {

        let mut keypair = Self {
            secret: SecretKey(<[u8; 32]>::from(secret_key_bytes)),
            public: PublicKey([0u8; 64]),
        };

        let return_code = unsafe {
            uecc::uECC_compute_public_key(
                &mut keypair.secret.0[0],
                &mut keypair.public.0[0],
                nist_p256(),
            )
        };

        if return_code == 1 {
            Ok(keypair)
        } else {
            Err(Error)
        }
    }
}

impl PublicKey {
    // pub fn verify_prehashed(&self, prehashed_message: &[u8; 32], signature: &Signature) -> bool {
    pub fn verify_prehashed(&self, prehashed_message: &[u8; 32], signature: impl AsArrayRef<SignatureBytes>) -> bool {
        let return_code = unsafe {
            uecc::uECC_verify(
                &self.0[0], // as *const u8,
                &prehashed_message[0],
                prehashed_message.len() as u32,
                &signature.as_array_ref()[0], // as *const u8,
                nist_p256(),
            )
        };
        return_code == 1
    }

    // pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
    pub fn verify(&self, message: &[u8], signature: impl AsArrayRef<SignatureBytes>) -> bool {
        let prehashed_message = prehash(message);
        self.verify_prehashed(&prehashed_message, signature)
    }

    // pub fn compress(&self) -> [u8; PUBLIC_KEY_COMPRESSED_LENGTH] {
    //     let mut compressed = [0u8; PUBLIC_KEY_COMPRESSED_LENGTH];
    //     unsafe {
    //         uecc::uECC_compress(
    //             &self.0[0], // as *const u8,
    //             &mut compressed[0],
    //             nist_p256(),
    //         )
    //     };
    //     compressed
    // }
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
    let result = unsafe { core::slice::from_raw_parts_mut(hash_result, DIGEST_LENGTH) } ;
    result.copy_from_slice(&data);
    // hprintln!("finish hash copied {:?}", result).ok();
    unsafe { HASHES += 1 };
}

