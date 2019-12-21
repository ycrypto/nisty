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
    let mut buf = unsafe { core::slice::from_raw_parts_mut(dest, size as usize) } ;
    for entry in buf {
        *entry = 1;
    }
    1
}

pub struct Keypair {
    pub secret: [u8; 32],
    pub public: [u8; 64],
}

impl Keypair {
    /// NB: need to set RNG first
    pub fn try_generate() -> Result<Self> {
        debug_assert!(unsafe { INITIALIZED } );
        let p256 = unsafe { uecc::uECC_secp256r1() };
        let mut keypair = Self { secret: [0u8; 32], public: [0u8; 64] };
        let return_code = unsafe {
            uecc::uECC_make_key(
                &mut keypair.secret[0] as *mut u8,
                &mut keypair.public[0] as *mut u8,
                p256,
            )
        };
        if return_code == 1 {
            Ok(keypair)
        } else {
            Err(Error)
        }
    }
}

