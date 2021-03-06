// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

//! # `Secwords`
//!
//! secure and safe password container.
//! - typed system
//! - memory safety
//! - unicode safety
//! <br>(no-std support)
//! ## Example
//! ```rust
//! # extern crate sha2;
//! use secwords::Password;
//! use sha2::Sha256; // can be any hasher from dyn Digest `digest` crate
//!
//! let plain = String::from("pa5$wOrs"); // <- example
//!
//! let pass1 = Password::<Sha256, 6>::new(plain).unwrap(); // min length = 6
//! let pass2: Password<Sha256, 6> = "pa5$wOrs".parse().unwrap();
//!
//! assert_eq!(pass1, pass2); // they are hashed, original is gone(safely)
//! assert_eq!(pass1.len(), 32); // fixed size `vep`(crate)
//! assert_eq!(pass1.as_ref(), pass2.as_slice());
//! assert_eq!(pass1.to_vec(), pass2.to_vec());
//!
//! assert_eq!(pass1, "pa5$wOrs");
//! assert_eq!(pass1, String::from("pa5$wOrs"));
//! assert_eq!(&pass1.to_hex().unwrap()[..20], "0f521249b366dd6e0acc");
//! assert_eq!(format!("{}", pass1), "***SECURE***"); // display
//! assert_eq!(format!("{:?}", pass1), "***SECURE***"); // debug
//!
//! let bytes = pass1.to_bytes(); // encode
//! let pass3 = Password::<Sha256, 6>::from_bytes(bytes).unwrap(); // decode
//! assert_eq!(pass1, pass3);
//!
//! let hex_string = pass1.to_hex().unwrap(); // encode
//! let pass3 = Password::<Sha256, 6>::from_hex(hex_string).unwrap(); // decode
//! assert_eq!(pass1, pass3);
//! ```
//! there are more examples in the `lib.rs`

#![deny(unsafe_code)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

mod password;
pub use password::Password;

extern crate hex;
extern crate unicode_normalization;
extern crate utils_results;
extern crate vep;
extern crate zeroize;

#[cfg(test)]
mod tests {
    use super::*;
    extern crate sha2;
    use self::sha2::Sha256;

    #[test]
    fn validator() {
        assert!("1234".parse::<Password<Sha256, 6>>().is_err());
        assert!("123456".parse::<Password<Sha256, 6>>().is_ok());
        assert!("?????????".parse::<Password<Sha256, 10>>().is_err());
        assert!("?????????".parse::<Password<Sha256, 9>>().is_ok());
    }
    #[test]
    fn encode_decode() {
        // bytes
        let password: Password<Sha256, 8> = "12345678".parse().unwrap();
        let bytes = password.to_bytes();
        assert_eq!(password.as_slice(), bytes.as_slice());
        let new_password = Password::<Sha256, 8>::from_bytes(bytes).unwrap();
        assert_eq!(password, new_password);

        // hex string
        let hex_string = password.to_hex().unwrap();
        let new_password = Password::<Sha256, 8>::from_hex(hex_string).unwrap();
        assert_eq!(password, new_password);
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
            "alie??nee??bre, a??cido, ?????????, ?????????????????????, ????????????".to_string(),
        )
        .unwrap();
        // testing encoding/decoding
        assert_eq!(
            password,
            "alie??nee??bre, a??cido, ?????????, ?????????????????????, ????????????"
        );
    }
    #[test]
    fn nested() {
        let first = Password::<Sha256, 5>::new("testman".to_string()).unwrap();
        assert_eq!(32, first.len());
        let second = Password::<Sha256, 5>::new(first.to_hex().unwrap()).unwrap();
        assert_eq!(32, second.len());
    }
}
