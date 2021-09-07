// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

use utils_results::*;

err! {
    InvalidLength => "invalid length:"
    Parse => "parse error:"
}

#[cfg(not(feature = "std"))]
use core::{
    cmp::{Eq, PartialEq},
    convert::AsRef,
    fmt::{self, Debug, Display},
    marker::PhantomData,
    ops::{Deref, Drop},
    str::{self, FromStr},
};

#[cfg(feature = "std")]
use std::{
    cmp::{Eq, PartialEq},
    convert::AsRef,
    fmt::{self, Debug, Display},
    marker::PhantomData,
    ops::{Deref, Drop},
    str::{self, FromStr},
};

use unicode_normalization::UnicodeNormalization;
use vep::{parts::Digest, Vep};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Password<D: Digest, const MIN_LENGTH: usize> {
    hashed_words: Vec<u8>,
    digester: PhantomData<D>,
}

impl<D: Digest, const MIN_LENGTH: usize> Password<D, MIN_LENGTH> {
    pub fn new<T: AsRef<str> + Zeroize>(plain_words: T) -> Result<Self> {
        Ok(Self {
            hashed_words: Self::extract_hashed_words(plain_words)?,
            digester: PhantomData,
        })
    }
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        if bytes.as_ref().len() != D::output_size() {
            return errbang!(err::Parse, "invalid length");
        }
        Ok(Self {
            hashed_words: bytes.as_ref().to_vec(),
            digester: PhantomData,
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.hashed_words.to_vec()
    }
    pub fn from_hex<T: AsRef<str>>(hex_string: T) -> Result<Self> {
        Ok(Self {
            hashed_words: errcast!(hex::decode(hex_string.as_ref()), err::Parse, "hex"),
            digester: PhantomData,
        })
    }
    pub fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(self.hashed_words.as_slice()))
    }
    pub fn eq_original<T: AsRef<str> + Zeroize>(&self, target: T) -> bool {
        self.hashed_words == Self::extract_hashed_words(target).unwrap_or_default()
    }

    #[inline]
    fn extract_hashed_words<T: AsRef<str> + Zeroize>(mut plain_words: T) -> Result<Vec<u8>> {
        let words = plain_words.as_ref();
        if words.len() < MIN_LENGTH {
            return errbang!(
                err::InvalidLength,
                "password must be more than {} length bytes. you are {}",
                MIN_LENGTH,
                words.len()
            );
        }

        let mut normed_words = Self::utf8_normalize(words);
        plain_words.zeroize();

        let hashed_words = Vep(D::new()).expand_and_then_reduce(&normed_words);
        normed_words.zeroize();

        Ok(hashed_words)
    }

    #[inline]
    fn utf8_normalize(s: &str) -> String {
        s.nfkd().to_string()
    }
}

impl<D: Digest, const MIN_LENGTH: usize> FromStr for Password<D, MIN_LENGTH> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl<D: Digest, const MIN_LENGTH: usize> AsRef<[u8]> for Password<D, MIN_LENGTH> {
    fn as_ref(&self) -> &[u8] {
        &self.hashed_words
    }
}

impl<D: Digest, const MIN_LENGTH: usize> Deref for Password<D, MIN_LENGTH> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.hashed_words
    }
}

impl<D: Digest, const MIN_LENGTH: usize> PartialEq for Password<D, MIN_LENGTH> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}
impl<D: Digest, const MIN_LENGTH: usize> PartialEq<String> for Password<D, MIN_LENGTH> {
    fn eq(&self, other: &String) -> bool {
        self.as_ref()
            .eq(&Self::extract_hashed_words(other.to_owned()).unwrap_or_default())
    }
}
impl<D: Digest, const MIN_LENGTH: usize> PartialEq<&str> for Password<D, MIN_LENGTH> {
    fn eq(&self, other: &&str) -> bool {
        self.as_ref()
            .eq(&Self::extract_hashed_words((*other).to_owned()).unwrap_or_default())
    }
}
impl<D: Digest, const MIN_LENGTH: usize> Eq for Password<D, MIN_LENGTH> {}

impl<D: Digest, const MIN_LENGTH: usize> Display for Password<D, MIN_LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***SECURE***")
    }
}

impl<D: Digest, const MIN_LENGTH: usize> Debug for Password<D, MIN_LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***SECURE***")
    }
}

impl<D: Digest, const MIN_LENGTH: usize> Zeroize for Password<D, MIN_LENGTH> {
    fn zeroize(&mut self) {
        self.hashed_words.zeroize();
    }
}

impl<D: Digest, const MIN_LENGTH: usize> Drop for Password<D, MIN_LENGTH> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
