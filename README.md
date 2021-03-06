# `Secwords`

[![CI][ci-badge]][ci-url]
[![Crates.io][crates-badge]][crates-url]
[![Licensed][license-badge]][license-url]
[![Twitter][twitter-badge]][twitter-url]

[ci-badge]: https://github.com/just-do-halee/secwords/actions/workflows/ci.yml/badge.svg
[crates-badge]: https://img.shields.io/crates/v/secwords.svg?labelColor=383636
[license-badge]: https://img.shields.io/crates/l/secwords?labelColor=383636
[twitter-badge]: https://img.shields.io/twitter/follow/do_halee?style=flat&logo=twitter&color=4a4646&labelColor=333131&label=just-do-halee

[ci-url]: https://github.com/just-do-halee/secwords/actions
[twitter-url]: https://twitter.com/do_halee
[crates-url]: https://crates.io/crates/secwords
[license-url]: https://github.com/just-do-halee/secwords

secure and safe password container.

* typed system
* memory safety
* unicode safety
<br>(no-std support)

| [Docs](https://docs.rs/secwords) | [Latest Note](https://github.com/just-do-halee/secwords/blob/main/CHANGELOG.md) |


```toml
[dependencies]
secwords = "2.1.1"
```

or

```toml
[dependencies]
secwords = { version = "2.1.1", default-features = false } # no-std
```

---


## `How to`
```rust
use secwords::Password;
use sha2::Sha256; // can be any hasher of dyn Digest `digest` crate

let plain = String::from("pa5$wOrs"); // <- example

let pass1 = Password::<Sha256, 6>::new(plain).unwrap(); // min length = 6
let pass2: Password<Sha256, 6> = "pa5$wOrs".parse().unwrap();

assert_eq!(pass1, pass2); // they are hashed, original is gone(safely)
assert_eq!(pass1.len(), 32); // fixed size `vep`(crate)
assert_eq!(pass1.as_ref(), pass2.as_slice());
assert_eq!(pass1.to_vec(), pass2.to_vec());

assert_eq!(pass1, "pa5$wOrs");
assert_eq!(pass1, String::from("pa5$wOrs"));
assert_eq!(&pass1.to_hex().unwrap()[..20], "0f521249b366dd6e0acc");
assert_eq!(format!("{}", pass1), "***SECURE***"); // display
assert_eq!(format!("{:?}", pass1), "***SECURE***"); // debug

let bytes = pass1.to_bytes(); // encode
let pass3 = Password::<Sha256, 6>::from_bytes(bytes).unwrap(); // decode
assert_eq!(pass1, pass3);

let hex_string = pass1.to_hex().unwrap(); // encode
let pass3 = Password::<Sha256, 6>::from_hex(hex_string).unwrap(); // decode
assert_eq!(pass1, pass3);
```
there are more examples in the `lib.rs`
