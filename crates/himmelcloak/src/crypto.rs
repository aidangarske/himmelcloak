/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use signature::Verifier;
use wolfssl_wolfcrypt::ecdsa::{P256Signature, P256VerifyingKey};
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::rsa_pkcs1v15::{Sha256, Signature as RsaSignature, VerifyingKey};
use wolfssl_wolfcrypt::sha::SHA256;

use crate::error::{Error, Result};

fn init() -> Result<()> {
    static INIT: OnceLock<std::result::Result<(), i32>> = OnceLock::new();
    INIT.get_or_init(wolfssl_wolfcrypt::wolfcrypt_init)
        .as_ref()
        .map_err(|_| Error::Crypto)
        .copied()
}

pub(crate) fn sha256(data: &[u8]) -> Result<[u8; 32]> {
    init()?;
    let mut sha = SHA256::new().map_err(|_| Error::Crypto)?;
    sha.update(data).map_err(|_| Error::Crypto)?;
    let mut digest = [0u8; 32];
    sha.finalize(&mut digest).map_err(|_| Error::Crypto)?;
    Ok(digest)
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    init()?;
    let rng = RNG::new().map_err(|_| Error::Crypto)?;
    let mut output = [0u8; N];
    rng.generate_block(&mut output).map_err(|_| Error::Crypto)?;
    Ok(output)
}

pub(crate) fn verify(alg: &str, jwk: &Value, message: &[u8], signature: &[u8]) -> Result<()> {
    init()?;
    match alg {
        "RS256" => verify_rsa(jwk, message, signature),
        "ES256" => verify_ec(jwk, message, signature),
        _ => Err(Error::TokenValidation("unsupported signing algorithm")),
    }
}

fn field(jwk: &Value, name: &str) -> Result<Vec<u8>> {
    let encoded = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or(Error::TokenValidation("missing JWK field"))?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::TokenValidation("invalid JWK encoding"))
}

fn verify_rsa(jwk: &Value, message: &[u8], signature: &[u8]) -> Result<()> {
    if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
        return Err(Error::TokenValidation("JWK type does not match algorithm"));
    }
    let modulus = field(jwk, "n")?;
    let exponent = field(jwk, "e")?;
    match modulus.len() {
        256 => verify_rsa_size::<256>(&modulus, &exponent, message, signature),
        384 => verify_rsa_size::<384>(&modulus, &exponent, message, signature),
        512 => verify_rsa_size::<512>(&modulus, &exponent, message, signature),
        _ => Err(Error::TokenValidation("unsupported RSA key size")),
    }
}

fn verify_rsa_size<const N: usize>(n: &[u8], e: &[u8], message: &[u8], bytes: &[u8]) -> Result<()> {
    let key = VerifyingKey::<Sha256, N>::from_components(n, e)
        .map_err(|_| Error::TokenValidation("invalid RSA key"))?;
    let signature = RsaSignature::<N>::try_from(bytes)
        .map_err(|_| Error::TokenValidation("invalid RSA signature length"))?;
    key.verify(message, &signature)
        .map_err(|_| Error::TokenValidation("invalid signature"))
}

fn verify_ec(jwk: &Value, message: &[u8], bytes: &[u8]) -> Result<()> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(Error::TokenValidation("JWK curve does not match algorithm"));
    }
    let x = field(jwk, "x")?;
    let y = field(jwk, "y")?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::TokenValidation("invalid P-256 point"));
    }
    let mut public = [0u8; 65];
    public[0] = 4;
    public[1..33].copy_from_slice(&x);
    public[33..].copy_from_slice(&y);
    let key = P256VerifyingKey::from_bytes(public);
    let signature = P256Signature::try_from(bytes)
        .map_err(|_| Error::TokenValidation("invalid ECDSA signature length"))?;
    key.verify(message, &signature)
        .map_err(|_| Error::TokenValidation("invalid signature"))
}
