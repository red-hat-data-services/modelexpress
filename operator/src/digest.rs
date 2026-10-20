// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SHA-256, from OpenSSL in the build that ships, so the validated library
//! does the hashing there.

/// OpenSSL could not compute SHA-256, e.g. the FIPS provider failed its self-tests.
#[derive(Debug, thiserror::Error)]
#[error("SHA-256 failed: {0}")]
pub struct DigestError(String);

#[cfg(feature = "tls-openssl")]
pub fn sha256(bytes: &[u8]) -> Result<[u8; 32], DigestError> {
    sha256_in(None, bytes).map_err(|err| DigestError(err.to_string()))
}

#[cfg(feature = "tls-openssl")]
fn sha256_in(
    ctx: Option<&openssl::lib_ctx::LibCtxRef>,
    bytes: &[u8],
) -> Result<[u8; 32], openssl::error::ErrorStack> {
    let md = openssl::md::Md::fetch(ctx, "SHA256", None)?;
    let mut hasher = openssl::md_ctx::MdCtx::new()?;
    hasher.digest_init(&md)?;
    hasher.digest_update(bytes)?;
    let mut out = [0u8; 32];
    hasher.digest_final(&mut out)?;
    Ok(out)
}

#[cfg(not(feature = "tls-openssl"))]
pub fn sha256(bytes: &[u8]) -> Result<[u8; 32], DigestError> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(bytes).into())
}

/// Lowercase hex, safe inside a Kubernetes object name.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        // writing to a String cannot fail
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::digest::{hex, sha256};

    #[test]
    fn known_vector() {
        assert_eq!(
            hex(&sha256(b"abc").expect("sha256")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_is_two_chars_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[cfg(feature = "tls-openssl")]
    #[test]
    fn provider_failure_is_an_error() {
        // Private context, so the process-wide OpenSSL state other tests use is untouched.
        let ctx = openssl::lib_ctx::LibCtx::new().expect("lib ctx");
        let _null = openssl::provider::Provider::load(Some(&ctx), "null").expect("null provider");
        assert!(super::sha256_in(Some(&ctx), b"abc").is_err());
    }
}
