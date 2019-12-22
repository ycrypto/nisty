//! Random numbers based on a seed

pub(crate) static mut RNG: Option<ChaCha20Rng> = None;

use crate::{
    SECRETKEY_LENGTH,
    Seed,
};

pub struct ChaCha20Rng {
    first_call: bool,
    seed: Seed,
    cipher: chacha20::ChaCha20,
}

// #[allow(unused_imports)]
// use cortex_m_semihosting::{dbg, hprintln};

impl ChaCha20Rng {
    pub fn new(seed: &[u8; SECRETKEY_LENGTH]) -> Self {
        use chacha20::stream_cipher::NewStreamCipher;
        let rng = ChaCha20Rng {
            first_call: true,
            seed: Seed(seed.clone()),
            cipher: chacha20::ChaCha20::new_var(seed, &[0u8; 12]).unwrap(),
        };
        rng
    }

    pub fn fill(&mut self, data: &mut [u8]) {
        // dbg!("in fill");

        debug_assert!(data.len() == SECRETKEY_LENGTH);
        if self.first_call {
            data.copy_from_slice(&self.seed.0);
            self.first_call = false;
            // hprintln!("filled from seed: {:?}", data).ok();
            // hprintln!("filled from seed").ok();
        } else {
            data.copy_from_slice(&[0u8; 32]);
            use chacha20::stream_cipher::SyncStreamCipher;
            self.cipher.apply_keystream(data);
            // hprintln!("filled from chacha: {:?}", data).ok();
            // hprintln!("filled from chacha").ok();
        }
    }

    // pub fn fill(data:
    // // experiment
    // let key = [0u8; 32];
    // let nonce = [0u8; 12];
    // use chacha20::stream_cipher::NewStreamCipher;
    // let cipher = chacha20::ChaCha20::new_var(&key, &nonce);
}

pub(crate) extern "C" fn chacha_rng(dest: *mut u8, size: u32) -> i32 {
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

