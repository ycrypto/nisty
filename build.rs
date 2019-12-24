use std::cfg;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET")?;

    let cortex_m4 = target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main");
    if cortex_m4 && cfg!(feature = "default") {
        // unfortunately, `compiler_error!` won't work here
        panic!("Cannot run bindgen for Cortex-M4/M33 targets. Try building without default features.");
    }

    Ok(())
}
