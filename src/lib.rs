// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

//! # `Secwords`
//!
//! secure and safe password (temporary) container.
//! - typed system
//! - memory safety
//! - unicode safety
//! <br>(no-std support)
//! ## Example
//! ```rust
//! use secwords::Password;
//! use sha2::Sha256; // can be any hasher from dyn Digest `digest` crate
//!
//! let plain = String::from("pa5$wOrs"); // <- example
//!
//! let pass1 = Password::<Sha256, 6>::new(plain).unwrap(); // min length = 6
//! let pass2: Password<Sha256, 6> = "pa5$wOrs".parse().unwrap();
//!
//! assert_eq!(pass1, pass2); // they are hashed, original is gone(safely)
//! assert_eq!(pass1.as_ref(), pass2.as_slice());
//! assert_eq!(pass1.to_vec(), pass2.to_vec());
//!
//! assert_eq!(pass1, "pa5$wOrs");
//! assert_eq!(pass1, String::from("pa5$wOrs"));
//! assert_eq!(&pass1.to_hex().unwrap()[..20], "923482c5795a1ce3ee33");
//! assert_eq!(pass1.to_hex().unwrap().len(), 512); // vep implementation
//! assert_eq!(format!("{}", pass1), "***SECURE***"); // display
//! assert_eq!(format!("{:?}", pass1), "***SECURE***"); // debug
//! ```
//! there are more examples in the `lib.rs`

#![deny(unsafe_code)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod password;
pub use password::Password;

extern crate utils_results;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn validator() {
        assert!("1234".parse::<Password<Sha256, 6>>().is_err());
        assert!("123456".parse::<Password<Sha256, 6>>().is_ok());
        assert!("이도하".parse::<Password<Sha256, 10>>().is_err());
        assert!("이도하".parse::<Password<Sha256, 9>>().is_ok());
    }
    #[test]
    fn parser() {
        let password: Password<Sha256, 8> = "12345678".parse().unwrap();
        let target = Password::<Sha256, 8>::new("12345678".to_string()).unwrap();
        assert_eq!(password, target);
    }
    #[test]
    fn equals() {
        let password1 = Password::<Sha256, 3>::new("1234".to_string()).unwrap();
        let password2: Password<Sha256, 3> = "1234".parse().unwrap();
        assert_eq!(password1, password2);
        assert_eq!(password1.as_ref(), password2.as_slice());
        assert_eq!(password1.to_vec(), password2.to_vec());
        assert_eq!(password1, "1234");
        assert_eq!(password1, String::from("1234"));
    }
    #[test]
    fn display() {
        let pass1 = Password::<Sha256, 3>::new("1234".to_string()).unwrap();
        let pass2 = Password::<Sha256, 3>::new("56789".to_string()).unwrap();
        assert_eq!(String::from("***SECURE***"), format!("{}", pass1));
        assert_eq!(format!("{}", pass1), format!("{}", pass2));
        assert!(pass1 != pass2);
    }
    #[test]
    fn normalizer() {
        let password = Password::<Sha256, 5>::new(
            "aliéneèbre, ácido, 쀏깕깕, ガバヴァぱばぐ, 十人十色".to_string(),
        )
        .unwrap();
        // testing encoding/decoding
        assert_eq!(
            password,
            "aliéneèbre, ácido, 쀏깕깕, ガバヴァぱばぐ, 十人十色"
        );
    }
    #[test]
    fn nested() {
        let first = Password::<Sha256, 5>::new("testman".to_string()).unwrap();
        assert_eq!(224, first.len());
        let second = Password::<Sha256, 5>::new(first.to_hex().unwrap()).unwrap();
        assert_eq!(14336, second.len());
    }
}
