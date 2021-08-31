// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

//! # `Secwords`
//!
//! secure and safe password (temporary) container.
//! - typed system
//! - memory safety
//! - unicode safety
//! <br>(no-std support)
//! ## How to
//! ```rust
//! use secwords::Password;
//!
//! let pass1 = Password::<6>::new("12345678").unwrap(); // min length = 6
//! let pass2: Password<6> = "12345678".parse().unwrap();
//!
//! assert_eq!(pass1, pass2);
//! assert_eq!(pass1, "12345678");
//! ```
//! there are more examples in the `lib.rs`

#![deny(unsafe_code)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod password;
pub use password::Password;

extern crate anyhow;

#[cfg(test)]
mod tests {
    use super::Password;
    use alloc::{format, string::String};
    use core::str;
    #[test]
    fn validator() {
        assert!("1234".parse::<Password<6>>().is_err());
        assert!("123456".parse::<Password<6>>().is_ok());
        assert!("이도하".parse::<Password<10>>().is_err());
        assert!("이도하".parse::<Password<9>>().is_ok());
    }
    #[test]
    fn parser() {
        let password: Password<8> = "12345678".parse().unwrap();
        let target = Password::<8>::new("12345678").unwrap();
        assert_eq!(password, target);
    }
    #[test]
    fn equals() {
        let password = Password::<3>::new("1234").unwrap();
        assert_eq!(password, String::from("1234"));
        assert_eq!(password, "1234".parse::<Password<3>>().unwrap());
        assert_eq!(password, "1234");
    }
    #[test]
    fn display() {
        let password = Password::<3>::new("1234").unwrap();
        assert_eq!(String::from("1234"), format!("{}", password));
    }
    #[test]
    fn normalizer() {
        let password =
            Password::<5>::new("aliéneèbre, ácido, 쀏깕깕, ガバヴァぱばぐ, 十人十色").unwrap();

        // testing nested
        let nested = Password::<5>::new(Password::<5>::new(&password).unwrap()).unwrap();
        assert_eq!(password, nested);
        assert_eq!(password.as_ref(), nested.as_ref());
        assert_eq!(password.as_str(), nested.as_str());
        assert_eq!(password.as_bytes(), nested.as_bytes());

        // testing encoding/decoding
        assert_eq!(
            str::from_utf8(password.as_bytes()).unwrap(),
            nested.as_str()
        );
        assert_eq!(
            password,
            "aliéneèbre, ácido, 쀏깕깕, ガバヴァぱばぐ, 十人十色"
        );
        assert!(
            str::from_utf8(password.as_bytes()).unwrap()
                != "aliéneèbre, ácido, 쀏깕깕, ガバヴァぱばぐ, 十人十色"
        ); // unnormed words
        assert_eq!(
            Password::<5>::new("aliéneèbre, ácido, 쀏깕깕, ガバヴァぱばぐ, 十人十色").unwrap(),
            str::from_utf8(password.as_bytes()).unwrap(),
        ); // normed words
    }
}
