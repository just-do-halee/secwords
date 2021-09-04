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

secure and safe password (temporary) container.

* typed system
* memory safety
* unicode safety
<br>(no-std support)

| [Docs](https://docs.rs/secwords) | [Latest Note](https://github.com/just-do-halee/secwords/blob/main/CHANGELOG.md) |


```toml
[dependencies]
secwords = "1.1.1"
```

or

```toml
[dependencies]
secwords = { version = "1.1.1", default-features = false } # no-std
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
assert_eq!(pass1.as_ref(), pass2.as_slice());
assert_eq!(pass1.to_vec(), pass2.to_vec());

assert_eq!(pass1, "pa5$wOrs");
assert_eq!(pass1, String::from("pa5$wOrs"));
assert_eq!(&pass1.to_hex().unwrap()[..20], "ed2757c9f4480697d789");
assert_eq!(pass1.to_hex().unwrap().len(), 512); // vep implementation
assert_eq!(format!("{}", pass1), "***SECURE***"); // display
assert_eq!(format!("{:?}", pass1), "***SECURE***"); // debug
```
there are more examples in the `lib.rs`
