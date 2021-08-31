// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

#[cfg(feature = "default")]
use core::{
    cmp::{Eq, PartialEq},
    convert::AsRef,
    fmt::{self, Debug, Display},
    ops::{Deref, Drop},
    result::Result,
    str::{self, FromStr},
};

#[cfg(feature = "std")]
use std::{
    cmp::{Eq, PartialEq},
    convert::AsRef,
    fmt::{self, Debug, Display},
    ops::{Deref, Drop},
    result::Result,
    str::{self, FromStr},
};

#[cfg(feature = "unicode-normalization")]
use unicode_normalization::UnicodeNormalization;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq)]
pub struct Password<const MIN_LENGTH: usize> {
    normed_words: String,
}

impl<const MIN_LENGTH: usize> Password<MIN_LENGTH> {
    pub fn new<T: AsRef<str>>(plain_words: T) -> Result<Self, String> {
        let words = plain_words.as_ref();
        if words.len() < MIN_LENGTH {
            return Err(format!(
                "password must be more than {} length bytes. you are {}",
                MIN_LENGTH,
                words.len()
            ));
        }
        Ok(Self {
            normed_words: words.nfkd().to_string(),
        })
    }
    pub fn as_str(&self) -> &str {
        self.normed_words.as_str()
    }
}

impl<const MIN_LENGTH: usize> FromStr for Password<MIN_LENGTH> {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl<const MIN_LENGTH: usize> AsRef<str> for Password<MIN_LENGTH> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl<const MIN_LENGTH: usize> Deref for Password<MIN_LENGTH> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.normed_words
    }
}

impl<const MIN_LENGTH: usize> PartialEq<String> for Password<MIN_LENGTH> {
    fn eq(&self, other: &String) -> bool {
        self.normed_words.eq(&other.nfkd().to_string())
    }
}

impl<const MIN_LENGTH: usize> PartialEq<&str> for Password<MIN_LENGTH> {
    fn eq(&self, other: &&str) -> bool {
        self.normed_words.eq(&other.nfkd().to_string())
    }
}

impl<const MIN_LENGTH: usize> Display for Password<MIN_LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.normed_words.as_str())
    }
}

impl<const MIN_LENGTH: usize> Drop for Password<MIN_LENGTH> {
    fn drop(&mut self) {
        self.normed_words.zeroize();
    }
}
