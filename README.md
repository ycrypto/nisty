<h1 align="center">nisty</h1>
<div align="center">
 <strong>
   NIST P256 signatures for Cortex-M4 microcontrollers
 </strong>
</div>

<br />

<div align="center">
  <!-- Crates version -->
  <a href="https://crates.io/crates/nisty">
    <img src="https://img.shields.io/crates/v/nisty.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/nisty">
    <img src="https://img.shields.io/crates/d/nisty.svg?style=flat-square"
      alt="Download" />
  </a>
  <!-- API docs -->
  <a href="https://docs.rs/nisty">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square"
      alt="main branch API docs" />
  </a>
</div>

## What is this?

**EXPERIMENTAL. WORK-IN-PROGRESS. DO NOT USE.**

Sometimes NIST P256 signatures need to be used.
This is an attempt to create a library that is misuse-resistent for that.

The intended targets are Cortex-M4 and Cortex-M33 microcontrollers.

As backend, we use [micro-ecc][micro-ecc], exposed via [micro-ecc-sys][micro-ecc-sys].

[micro-ecc]: https://github.com/kmackay/micro-ecc
[micro-ecc-sys]: https://crates.io/crates/micro-ecc-sys

#### License

<sup>Nisty is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.</sup>
<sup>micro-ecc is licensed under [BSD-2-Clause](https://github.com/kmackay/micro-ecc/blob/master/LICENSE.txt).</sup>
<br>
<sub>Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.</sub>
