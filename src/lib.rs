#![no_std]
/*! Library for [NIST P-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) (aka secp256r1) signatures, for when you really can't avoid them.

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

## Examples
```
let seed = [0u8; 32]; // use an actually entropic seed (hw RNG, ChaCha20,... )

assert!(nisty::Keypair::try_from_bytes(&seed).is_err()); // zero is invalid as secret scalar
assert!(nisty::Keypair::generate(&seed, 1).is_err()); // equivalent to previous line
assert!(nisty::Keypair::generate(&seed, 2).is_ok()); // equivalent to following line
let keypair = nisty::Keypair::generate_patiently(&seed);

let message = b"slip and slide communication";
let signature = keypair.sign(message);
assert!(keypair.verify(message, signature));
assert!(!keypair.verify(b"suspicious minds", signature));

// serialize keys and signatures
let public_key_bytes: [u8; 64] = keypair.public.to_bytes();
let mut signature_bytes: [u8; 64] = signature.into();
// deserialize keys and signatures
let public_key = nisty::PublicKey::try_from_bytes(&public_key_bytes).unwrap();
assert!(public_key.verify(message, signature_bytes));
signature_bytes[37] = b'X';
assert!(!public_key.verify(message, signature_bytes));
```

## Microcontrollers
Because `bindgen`, `no_std` and Rust's limited feature tree handling don't play nice
together ([#4866](https://github.com/rust-lang/cargo/issues/4866)),
on microcontrollers the bindings to `micro-ecc` need to be pre-generated.

For Cortex-M4 and Cortex-M33 microcontrollers, they are packaged, and it is sufficient
to use `nisty` as follows:

```toml
[dependencies.nisty]
default-features = false
```

When compiled as release build, these platforms automatically pick up UMAAL assembly optimizations.

On an NXP LPC55S69, signature generation then takes around 6.9M cycles, signature verification around 7.6M.
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

/// This library's result type.
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

impl AsArrayRef<SeedBytes> for &Seed {
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
/// Secret part of a keypair, a scalar. Signs messages.
#[derive(Clone,Debug,PartialEq)]
pub struct SecretKey(SecretKeyBytes);

impl core::convert::TryFrom<&SecretKeyBytes> for SecretKey {
    type Error = Error;

    fn try_from(secret_key_bytes: &SecretKeyBytes) -> Result<SecretKey> {
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

impl AsArrayRef<SecretKeyBytes> for &SecretKey {
    fn as_array_ref(&self) -> &SecretKeyBytes {
        &self.0
    }
}

impl SecretKey {
    /// Sign arbitrary data.
    ///
    /// Convenience method, calls `sign_prehashed` on `prehash(message)`.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let prehashed_message = prehash(message);
        self.sign_prehashed(&prehashed_message)
    }

    /// Sign data that is prehashed, probably with SHA-256.
    pub fn sign_prehashed(&self, prehashed_message: &[u8; DIGEST_LENGTH]) -> Signature {
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
            uecc::uECC_sign_deterministic(
                &self.0[0],
                &prehashed_message[0],
                prehashed_message.len() as u32,
                &hash_context,
                &mut signature.0[0],
                nist_p256(),
            )
        };
        assert_eq!(return_code, 1);
        signature
    }
}

impl SecretKey {
    pub fn try_from_bytes(secret_key_bytes: &SecretKeyBytes) -> Result<Self> {
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
/// Public part of a keypair, a point on the curve. Verifies signatures.
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

impl core::convert::TryFrom<&PublicKeyBytes> for PublicKey {
    type Error = Error;

    fn try_from(public_key_bytes: &PublicKeyBytes) -> Result<PublicKey> {
        let return_code = unsafe {
            uecc::uECC_valid_public_key(
                &public_key_bytes[0],
                nist_p256(),
            )
        };
        if return_code == 1 {
            Ok(PublicKey(*public_key_bytes))
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

impl AsArrayRef<PublicKeyBytes> for &PublicKey {
    fn as_array_ref(&self) -> &PublicKeyBytes {
        &self.0
    }
}

impl PublicKey {
    /// Verify that a claimed signature for a message is valid.
    pub fn verify(&self, message: &[u8], signature: impl AsArrayRef<SignatureBytes>) -> bool {
        let prehashed_message = prehash(message);
        self.verify_prehashed(&prehashed_message, signature)
    }

    /// Verify that a claimed signature for a prehashed message is valid.
    pub fn verify_prehashed(&self, prehashed_message: &[u8; DIGEST_LENGTH], signature: impl AsArrayRef<SignatureBytes>) -> bool {
        let return_code = unsafe {
            uecc::uECC_verify(
                &self.0[0],
                &prehashed_message[0],
                DIGEST_LENGTH as u32,
                &signature.as_array_ref()[0],
                nist_p256(),
            )
        };
        return_code == 1
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

impl PublicKey {
     pub fn try_from_bytes(public_key_bytes: &PublicKeyBytes) -> Result<Self> {
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

/// Create keys, sign messages, verify signatures.
///
/// Key generation from a seed needs no further entropic input.
/// Signatures are always deterministic, they need no entropic input.
///
/// As a user of this library, you need to **think long and hard
/// whether the seeds you use to generate keys are sufficiently entropic**. But after
/// that, no more such thought is necessary – in particular, entropy failure during
/// signing will never reveal your keys.
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

impl AsArrayRef<SignatureBytes> for &Signature {
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

/// Convenience function, calculates SHA256 hash digest of a slice of bytes.
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
    /// **IT IS YOUR RESPONSIBILITY TO THINK ABOUT WHETHER YOUR SEEDS ARE ENTROPIC.**
    ///
    /// Approach: if the given seed does not correspond to a secret key,
    /// we repeatedly compute its SHA-256 digest, until it passes muster,
    /// at most `tries` times.
    ///
    /// Instead of calling with `tries = 1`, consider using
    /// [`Keypair::try_from_bytes`](struct.Keypair.html#method.try_from_bytes) directly.
    ///
    /// If you can't make up your mind about how many `tries` to allow, use
    /// [`Keypair::generate_patiently`](struct.Keypair.html#method.generate_patiently) instead.
    pub fn generate(seed: impl AsArrayRef<SeedBytes>, tries: usize) -> Result<Keypair> {
        let mut secret = <[u8; SECRET_KEY_LENGTH]>::from(*seed.as_array_ref());

        use core::convert::TryFrom;
        for _attempt in 0..tries {

            let candidate = Keypair::try_from(&secret);
            if candidate.is_ok() {
                return candidate;
            }
            secret = prehash(&secret);
        }

        Err(Error)
    }

    /// Like [`Keypair::generate`](struct.Keypair.html#method.generate), but keeps on
    /// trying indefinitely.
    pub fn generate_patiently(seed: impl AsArrayRef<SeedBytes>) -> Keypair {
        let mut secret = <[u8; SECRET_KEY_LENGTH]>::from(*seed.as_array_ref());
        use core::convert::TryFrom;
        loop {
            let candidate = Keypair::try_from(&secret);
            match candidate {
                Ok(keypair) => return keypair,
                _ => {},
            };
            secret = prehash(&secret);
        }
    }

    /// Return keypair with given bytes as secret key, if valid.
    ///
    /// If uncertain whether the bytes are a valid secret key,
    /// try [`Keypair::generate`](struct.Keypair.html#method.generate) with `tries > 1` instead.
    pub fn try_from_bytes(secret_key_bytes: &SecretKeyBytes) -> Result<Keypair> {
        use core::convert::TryFrom;
        Keypair::try_from(secret_key_bytes)
    }

    /// Consume the keypair and return its secret and public components.
    ///
    /// Use the secret key to sign, use the public key to verify.
    pub fn split(self) -> (SecretKey, PublicKey) {
        (self.secret, self.public)
    }

    /// Sign arbitrary data.
    /// Delegates to [`SecretKey::sign`](struct.SecretKey.html#method.sign).
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    /// Sign data that is prehashed, probably with SHA-256.
    /// Delegates to [`SecretKey::sign_prehashed`](struct.SecretKey.html#method.sign_prehashed).
    pub fn sign_prehashed(&self, prehashed_message: &[u8; DIGEST_LENGTH]) -> Signature {
        self.secret.sign_prehashed(prehashed_message)
    }

    /// Verify that a claimed signature for a message is valid.
    /// Delegates to [`PublicKey::verify`](struct.PublicKey.html#method.verify).
    pub fn verify(&self, message: &[u8], signature: impl AsArrayRef<SignatureBytes>) -> bool {
        self.public.verify(message, signature)
    }

    /// Verify that a claimed signature for a prehashed message is valid.
    /// Delegates to [`PublicKey::verify_prehashed`](struct.PublicKey.html#method.verify_prehashed).
    pub fn verify_prehashed(&self, prehashed_message: &[u8; DIGEST_LENGTH], signature: impl AsArrayRef<SignatureBytes>) -> bool {
        self.public.verify_prehashed(prehashed_message, signature)
    }

}

impl core::convert::TryFrom<&SecretKeyBytes> for Keypair {

    type Error = Error;

    fn try_from(secret_key_bytes: &SecretKeyBytes) -> Result<Self> {

        let mut keypair = Self {
            secret: SecretKey(<[u8; SECRET_KEY_LENGTH]>::from(*secret_key_bytes)),
            public: PublicKey([0u8; PUBLIC_KEY_LENGTH]),
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

impl From<&SecretKey> for Keypair {
    fn from(secret_key: &SecretKey) -> Self {
        let public_key = PublicKey::from(secret_key);
        Keypair {
            secret: secret_key.clone(),
            public: public_key,
        }
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        let mut keypair = Keypair {
            secret: secret_key.clone(),
            public: PublicKey([0u8; PUBLIC_KEY_LENGTH]),
        };

        let return_code = unsafe {
            uecc::uECC_compute_public_key(
                &mut keypair.secret.0[0],
                &mut keypair.public.0[0],
                nist_p256(),
            )
        };

        // infallible, as SecretKey cannot be created unchecked
        debug_assert!(return_code == 1);
        keypair.public
    }
}

#[repr(C)]
struct ShaHashContext {
    context: uecc::uECC_HashContext,
    sha: sha2::Sha256,
}

extern "C" fn uecc_init_hash(context: *const uecc::uECC_HashContext) {
    let sha2 = unsafe { &mut(*(context as *mut ShaHashContext)).sha } ;
    use sha2::digest::Reset;
    sha2.reset();
}

extern "C" fn uecc_update_hash(context: *const uecc::uECC_HashContext, message: *const u8, message_size: u32) {
    let sha2 = unsafe { &mut(*(context as *mut ShaHashContext)).sha };
    let buf = unsafe { core::slice::from_raw_parts(message, message_size as usize) } ;
    use sha2::digest::Input;
    sha2.input(&buf);
}

static mut HASHES: u32 = 0;

/// How many hash digests were calculated for signatures so far.
pub unsafe fn hash_calls() -> u32 {
    HASHES
}

extern "C" fn uecc_finish_hash(context: *const uecc::uECC_HashContext, hash_result: *mut u8) {
    let sha2 = unsafe { &mut(*(context as *mut ShaHashContext)).sha };
    use sha2::digest::Digest;
    let data = sha2.result_reset();
    let result = unsafe { core::slice::from_raw_parts_mut(hash_result, DIGEST_LENGTH) } ;
    result.copy_from_slice(&data);
    unsafe { HASHES += 1 };
}

