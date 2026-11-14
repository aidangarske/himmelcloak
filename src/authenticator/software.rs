/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Software (virtual) `WebAuthnAdapter` for CI/tests, headless passkey flows, no hardware.
//! Feature: `webauthn-virtual`.

// RP ID hash (32 bytes), flags (1 byte), and signature counter (4 bytes).
const AUTHENTICATOR_DATA_LEN: usize = 37;
// Two 32-byte integers may each need a leading zero plus DER tags/lengths.
const MAX_P256_DER_SIG_LEN: usize = 72;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
// Local resource limits for this single-credential virtual backend.
const MAX_ALLOW_CREDENTIALS: usize = 64;
const MAX_CREDENTIAL_ID_LEN: usize = 1023;
const MAX_USER_HANDLE_LEN: usize = 64;

// Keep signing-key access and counter updates private. Avoid Debug and Clone
// because this state contains a private signing key.
struct InMemoryCredential {
    signing_key: wolfssl_wolfcrypt::ecdsa::P256SigningKey,
    // Bind this key to one relying party, rather than using it for any RP ID.
    rp_id: String,
    // Public opaque identifier: distinct from both the private key and user ID.
    credential_id: Vec<u8>,
    // Starts at zero; increments only after assertion signing and encoding succeed.
    sign_count: u32,
    // Registration is one-shot even before the first assertion advances the counter.
    registered: bool,
}

/// A single-credential virtual authenticator for tests and headless development.
/// Its key exists only in memory and is lost when this instance is dropped.
/// Calling get_assertion simulates user presence for this virtual backend;
/// it does not perform a physical touch or user verification.
/// Requests requiring user verification return [`crate::Error::UnsupportedFactor`].
/// Malformed requests return [`crate::Error::AuthenticationRejected`]: RP IDs
/// and credential IDs must be nonempty, allow lists are limited to 64 entries,
/// and each credential ID is limited to 1023 bytes, including unmatched entries.
///
/// Internal state uses `RefCell`, so this type is not `Sync`. A driver sharing
/// it across Tokio tasks will need a mutex around the mutable credential state.
pub struct SoftwareAuthenticator {
    // The shared-reference adapter API still needs mutable signing and counter state.
    credential: std::cell::RefCell<InMemoryCredential>,
}

impl SoftwareAuthenticator {
    /// Provision one fresh credential locally.
    /// Use a new instance for each registration ceremony, then retain it for assertions.
    /// [`super::WebAuthnAdapter::make_credential`] exports a `none` attestation object;
    /// the caller owns the challenge, origin binding, clientDataJSON, and HTTP posting.
    pub fn new(rp_id: String) -> crate::Result<Self> {
        let credential = InMemoryCredential::new(rp_id)?;
        Ok(Self {
            credential: std::cell::RefCell::new(credential),
        })
    }

    // Known, disposable key material is available only in the crate's test build.
    #[cfg(test)]
    pub(crate) fn realm_fixture() -> Self {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/keycloak/software-credential.json"
        ))
        .unwrap();
        let decode = |name: &str| {
            URL_SAFE_NO_PAD
                .decode(fixture[name].as_str().unwrap())
                .unwrap()
        };
        let public: [u8; 65] = decode("publicKey").try_into().unwrap();
        let scalar: [u8; 32] = decode("privateScalar").try_into().unwrap();
        let signing_key = wolfssl_wolfcrypt::ecdsa::P256SigningKey::import_x963(
            &public,
            &scalar,
            crate::crypto::rng().unwrap(),
        )
        .unwrap();
        Self {
            credential: std::cell::RefCell::new(InMemoryCredential {
                signing_key,
                rp_id: fixture["rpId"].as_str().unwrap().to_owned(),
                credential_id: decode("credentialId"),
                sign_count: 0,
                registered: false,
            }),
        }
    }

    /// Copy the public credential ID for use in an allowed-credentials list.
    pub fn credential_id(&self) -> Vec<u8> {
        self.credential.borrow().credential_id.clone()
    }

    /// Copy this credential's ES256 public key for fixture registration or verification.
    ///
    /// Returns the 65-byte uncompressed SEC1 / ANSI X9.63 P-256 encoding:
    /// `0x04 || x || y`, with 32-byte coordinates. Together with
    /// [`Self::credential_id`], this identifies the locally provisioned credential.
    /// This is public key material only, not a WebAuthn registration response or
    /// a COSE-encoded key; callers must encode it as required by their fixture.
    pub fn public_key(&self) -> Vec<u8> {
        use signature::Keypair;

        self.credential
            .borrow()
            .signing_key
            .verifying_key()
            .as_ref()
            .to_vec()
    }
}

impl super::WebAuthnAdapter for SoftwareAuthenticator {
    fn make_credential(
        &self,
        request: &super::WebAuthnCreateRequest,
    ) -> crate::Result<super::WebAuthnRegistration> {
        use signature::Keypair;
        let mut credential = self
            .credential
            .try_borrow_mut()
            .map_err(|_| crate::Error::Crypto)?;
        if request.rp.id.is_empty()
            || request.rp.id != credential.rp_id
            || request.rp.name.is_empty()
            || request.user.name.is_empty()
            || request.user.id.is_empty()
            || request.user.id.len() > MAX_USER_HANDLE_LEN
            || request.exclude_credentials.len() > MAX_ALLOW_CREDENTIALS
            || request.exclude_credentials.iter().any(|item| {
                item.id.is_empty()
                    || item.id.len() > MAX_CREDENTIAL_ID_LEN
                    || item.id == credential.credential_id
            })
        {
            return Err(crate::Error::AuthenticationRejected);
        }
        if !request.algorithms.contains(&-7)
            || request.resident_key_required
            || matches!(request.user_verification, super::UserVerification::Required)
        {
            return Err(crate::Error::UnsupportedFactor);
        }
        // A new instance provisions one key. Never re-register an already-used credential.
        if credential.registered || credential.sign_count != 0 {
            return Err(crate::Error::AuthenticationRejected);
        }
        let rp_hash = crate::crypto::sha256(credential.rp_id.as_bytes())?;
        let mut data = build_assertion_authenticator_data(&rp_hash, FLAG_UP | FLAG_AT, 0).to_vec();
        data.extend_from_slice(&[0; 16]); // No identifying AAGUID for this virtual backend.
        let id_len =
            u16::try_from(credential.credential_id.len()).map_err(|_| crate::Error::Crypto)?;
        data.extend_from_slice(&id_len.to_be_bytes());
        data.extend_from_slice(&credential.credential_id);
        let public = credential.signing_key.verifying_key();
        // Fixed COSE EC2 key: kty=2, alg=-7, crv=1, x and y are 32-byte coordinates.
        data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        data.extend_from_slice(&public.as_ref()[1..33]);
        data.extend_from_slice(&[0x22, 0x58, 0x20]);
        data.extend_from_slice(&public.as_ref()[33..65]);
        // WebAuthn §6.5: fmt=none carries an empty statement, without an attestation signature.
        // This fixed single-credential layout fits a CBOR byte string with one length byte.
        let mut attestation = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58".to_vec();
        attestation.push(u8::try_from(data.len()).map_err(|_| crate::Error::Crypto)?);
        attestation.extend_from_slice(&data);
        let registration = super::WebAuthnRegistration {
            credential_id: credential.credential_id.clone(),
            attestation_object: attestation,
        };
        credential.registered = true;
        Ok(registration)
    }

    fn get_assertion(
        &self,
        request: &super::WebAuthnGetRequest,
    ) -> crate::Result<super::WebAuthnAssertion> {
        use signature::SignerMut;
        use wolfssl_wolfcrypt::ecdsa::P256Signature;

        // A borrow conflict is an internal failure, not a rejected login.
        let mut credential = self
            .credential
            .try_borrow_mut()
            .map_err(|_| crate::Error::Crypto)?;
        credential.validate_request(request)?;
        // Never wrap the counter back to zero. Do not commit it until all
        // fallible signing and encoding operations have succeeded.
        let next_count = credential
            .sign_count
            .checked_add(1)
            .ok_or(crate::Error::AuthenticationRejected)?;
        let data = assertion_authenticator_data(&credential.rp_id, false, next_count)?;

        // WebAuthn signs authenticatorData followed by the client's data hash.
        // SignerMut hashes this combined message internally with SHA-256.
        let mut message =
            Vec::with_capacity(AUTHENTICATOR_DATA_LEN + request.client_data_hash.len());
        message.extend_from_slice(&data);
        message.extend_from_slice(&request.client_data_hash);
        let raw_signature: P256Signature = credential
            .signing_key
            .try_sign(&message)
            .map_err(|_| crate::Error::Crypto)?;

        // The signing wrapper exposes 64 raw r || s bytes, while an ES256
        // WebAuthn assertion uses an ASN.1 DER sequence of the two integers.
        // Use wolfCrypt's existing encoder rather than hand-writing DER rules.
        let raw = raw_signature.as_ref();
        let mut der = [0u8; MAX_P256_DER_SIG_LEN];
        let length = wolfssl_wolfcrypt::ecc::ECC::rs_bin_to_sig(&raw[..32], &raw[32..], &mut der)
            .map_err(|_| crate::Error::Crypto)?;
        let assertion = super::WebAuthnAssertion {
            authenticator_data: data.to_vec(),
            signature: der[..length].to_vec(),
            credential_id: credential.credential_id.clone(),
            // This initial backend handles only explicitly allowed credentials.
            user_handle: None,
        };
        credential.sign_count = next_count;
        Ok(assertion)
    }
}

impl InMemoryCredential {
    // Validate the request against this stored credential before signing.
    // This initial authenticator has no user-verification mechanism and only
    // handles explicitly allowed credentials (no discoverable-credential flow).
    fn validate_request(&self, request: &super::WebAuthnGetRequest) -> crate::Result<()> {
        // Reject malformed lists before scanning for a match, even if the first ID matches.
        if request.rp_id.is_empty()
            || request.allow_credentials.len() > MAX_ALLOW_CREDENTIALS
            || request
                .allow_credentials
                .iter()
                .any(|allowed| allowed.id.is_empty() || allowed.id.len() > MAX_CREDENTIAL_ID_LEN)
        {
            return Err(crate::Error::AuthenticationRejected);
        }
        if request.rp_id != self.rp_id {
            return Err(crate::Error::AuthenticationRejected);
        }
        // Empty allow-lists are unsupported by this explicit-credential backend.
        if !request
            .allow_credentials
            .iter()
            .any(|allowed| allowed.id == self.credential_id)
        {
            return Err(crate::Error::AuthenticationRejected);
        }
        // Required verification needs a capable backend; setting UV alone is insufficient.
        if matches!(request.user_verification, super::UserVerification::Required) {
            return Err(crate::Error::UnsupportedFactor);
        }
        Ok(())
    }

    // This is local provisioning for tests, not a CTAP makeCredential handler.
    fn new(rp_id: String) -> crate::Result<Self> {
        if rp_id.is_empty() {
            return Err(crate::Error::InvalidConfiguration(
                "empty authenticator RP ID",
            ));
        }
        // Generate a fresh opaque ID independently of signing-key setup.
        // The 32-byte ID length is our implementation choice, not a private key.
        let credential_id = crate::crypto::random_bytes::<32>()?.to_vec();
        let rng = crate::crypto::rng()?;
        let signing_key = wolfssl_wolfcrypt::ecdsa::P256SigningKey::generate(rng)
            .map_err(|_| crate::Error::Crypto)?;
        Ok(Self {
            signing_key,
            rp_id,
            credential_id,
            sign_count: 0,
            registered: false,
        })
    }
}

// WebAuthn §6.1 (https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data):
// an assertion without extensions has a 32-byte RP ID
// hash, one flags byte, and a four-byte signature counter. Registration data
// and extensions are deliberately not appended by this layout helper.
fn build_assertion_authenticator_data(
    rp_id_hash: &[u8; 32],
    flags: u8,
    sign_count: u32,
) -> [u8; AUTHENTICATOR_DATA_LEN] {
    let mut data = [0u8; AUTHENTICATOR_DATA_LEN];
    data[..32].copy_from_slice(rp_id_hash);
    data[32] = flags;
    // WebAuthn encodes the signature counter in network byte order.
    data[33..AUTHENTICATOR_DATA_LEN].copy_from_slice(&sign_count.to_be_bytes());
    // This only assembles bytes. The caller must compute SHA-256(rpId) and
    // choose flags consistent with actual presence/verification and no AT/ED.
    data
}

// Build this software authenticator's assertion bytes from the RP ID itself.
// The caller supplies whether user verification actually succeeded; this helper
// does not perform verification or establish user presence. Its current policy
// assumes presence was established and emits no backup, registration, or extension bits.
fn assertion_authenticator_data(
    rp_id: &str,
    user_verified: bool,
    sign_count: u32,
) -> crate::Result<[u8; AUTHENTICATOR_DATA_LEN]> {
    // Hash the RP ID itself, not a URL or the client data hash.
    let rp_id_hash = crate::crypto::sha256(rp_id.as_bytes())?;
    let flags = if user_verified {
        FLAG_UP | FLAG_UV
    } else {
        FLAG_UP
    };
    Ok(build_assertion_authenticator_data(
        &rp_id_hash,
        flags,
        sign_count,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration_request() -> super::super::WebAuthnCreateRequest {
        use super::super::{
            UserVerification, WebAuthnCreateRequest, WebAuthnRpEntity, WebAuthnUserEntity,
        };

        WebAuthnCreateRequest {
            rp: WebAuthnRpEntity {
                id: "example.com".into(),
                name: "Example".into(),
            },
            user: WebAuthnUserEntity {
                id: b"test-user".to_vec(),
                name: "test-user".into(),
                display_name: "Test User".into(),
            },
            client_data_hash: [0xab; 32],
            algorithms: vec![-7],
            exclude_credentials: vec![],
            user_verification: UserVerification::Preferred,
            resident_key_required: false,
        }
    }

    #[test]
    fn registration_encodes_none_attestation_and_preserves_assertion_counter() {
        use super::super::{
            CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
        };
        let authenticator = SoftwareAuthenticator::new("example.com".into()).unwrap();
        let mut request = registration_request();
        request.algorithms = vec![-257, -7];
        let registration = authenticator.make_credential(&request).unwrap();
        assert_eq!(registration.credential_id, authenticator.credential_id());
        let object = &registration.attestation_object;
        let prefix = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58\xa4";
        assert_eq!(&object[..prefix.len()], prefix);
        let data = &object[prefix.len()..];
        assert_eq!(data.len(), 164);
        // Independent SHA-256("example.com").
        assert_eq!(
            &data[..32],
            &[
                0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11, 0x80, 0x34,
                0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab, 0x13, 0xd2, 0x12, 0x55,
                0x86, 0xce, 0x19, 0x47
            ]
        );
        assert_eq!(data[32], 0x41); // UP + AT, without UV.
        assert_eq!(&data[33..53], &[0; 20]); // Initial counter and AAGUID.
        assert_eq!(&data[53..55], &[0, 32]);
        assert_eq!(&data[55..87], registration.credential_id);
        assert_eq!(
            &data[87..97],
            &[0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20]
        );
        let public = authenticator.public_key();
        assert_eq!(&data[97..129], &public[1..33]);
        assert_eq!(&data[129..132], &[0x22, 0x58, 0x20]);
        assert_eq!(&data[132..], &public[33..]);
        assert_eq!(authenticator.credential.borrow().sign_count, 0);
        assert!(matches!(
            authenticator.make_credential(&request),
            Err(crate::Error::AuthenticationRejected)
        ));
        assert_eq!(authenticator.credential.borrow().sign_count, 0);
        let assertion = authenticator
            .get_assertion(&WebAuthnGetRequest {
                rp_id: request.rp.id.clone(),
                client_data_hash: [0; 32],
                allow_credentials: vec![CredentialDescriptor {
                    id: authenticator.credential_id(),
                }],
                user_verification: UserVerification::Preferred,
            })
            .unwrap();
        assert_eq!(&assertion.authenticator_data[33..], &1u32.to_be_bytes());
        assert!(matches!(
            authenticator.make_credential(&request),
            Err(crate::Error::AuthenticationRejected)
        ));
    }

    #[test]
    fn registration_rejects_unsupported_options_and_excluded_credentials() {
        use super::super::{CredentialDescriptor, UserVerification, WebAuthnAdapter};
        let authenticator = SoftwareAuthenticator::new("example.com".into()).unwrap();
        let valid = registration_request;
        let mut wrong_rp = valid();
        wrong_rp.rp.id = "other.example".into();
        let mut excluded = valid();
        excluded.exclude_credentials.push(CredentialDescriptor {
            id: authenticator.credential_id(),
        });
        let mut malformed = valid();
        malformed
            .exclude_credentials
            .push(CredentialDescriptor { id: vec![] });
        let mut empty_rp = valid();
        empty_rp.rp.id.clear();
        let mut empty_rp_name = valid();
        empty_rp_name.rp.name.clear();
        let mut empty_username = valid();
        empty_username.user.name.clear();
        let mut empty_user_id = valid();
        empty_user_id.user.id.clear();
        let mut oversized_user_id = valid();
        oversized_user_id.user.id = vec![0; MAX_USER_HANDLE_LEN + 1];
        for request in [
            wrong_rp,
            excluded,
            malformed,
            empty_rp,
            empty_rp_name,
            empty_username,
            empty_user_id,
            oversized_user_id,
        ] {
            assert!(matches!(
                authenticator.make_credential(&request),
                Err(crate::Error::AuthenticationRejected)
            ));
            assert!(!authenticator.credential.borrow().registered);
            assert_eq!(authenticator.credential.borrow().sign_count, 0);
        }
        let mut algorithm = valid();
        algorithm.algorithms = vec![-257];
        let mut uv = valid();
        uv.user_verification = UserVerification::Required;
        let mut resident = valid();
        resident.resident_key_required = true;
        for request in [algorithm, uv, resident] {
            assert!(matches!(
                authenticator.make_credential(&request),
                Err(crate::Error::UnsupportedFactor)
            ));
            assert!(!authenticator.credential.borrow().registered);
            assert_eq!(authenticator.credential.borrow().sign_count, 0);
        }
        let guard = authenticator.credential.borrow();
        assert!(matches!(
            authenticator.make_credential(&valid()),
            Err(crate::Error::Crypto)
        ));
        assert!(!guard.registered);
        assert_eq!(guard.sign_count, 0);
        drop(guard);
        assert!(authenticator.make_credential(&valid()).is_ok());
    }

    #[test]
    fn registration_rejects_oversized_exclusions_and_allows_retry() {
        use super::super::{CredentialDescriptor, WebAuthnAdapter};

        let mut too_many = registration_request();
        too_many.exclude_credentials = (0..=MAX_ALLOW_CREDENTIALS)
            .map(|_| CredentialDescriptor { id: vec![0] })
            .collect();
        let mut oversized_id = registration_request();
        oversized_id.exclude_credentials.push(CredentialDescriptor {
            id: vec![0; MAX_CREDENTIAL_ID_LEN + 1],
        });
        for request in [too_many, oversized_id] {
            let authenticator = SoftwareAuthenticator::new("example.com".into()).unwrap();
            assert!(matches!(
                authenticator.make_credential(&request),
                Err(crate::Error::AuthenticationRejected)
            ));
            let state = authenticator.credential.borrow();
            assert!(!state.registered);
            assert_eq!(state.sign_count, 0);
            drop(state);
            let registration = authenticator
                .make_credential(&registration_request())
                .expect("invalid exclusions must not consume registration");
            assert_eq!(registration.credential_id, authenticator.credential_id());
            assert!(authenticator.credential.borrow().registered);
            assert_eq!(authenticator.credential.borrow().sign_count, 0);
        }
    }

    #[test]
    fn registration_accepts_exclusion_and_user_handle_boundaries() {
        use super::super::{CredentialDescriptor, WebAuthnAdapter};

        let mut maximum_list = registration_request();
        maximum_list.exclude_credentials = (0..MAX_ALLOW_CREDENTIALS)
            .map(|_| CredentialDescriptor { id: vec![0] })
            .collect();
        let mut maximum_id = registration_request();
        maximum_id.exclude_credentials.push(CredentialDescriptor {
            id: vec![0; MAX_CREDENTIAL_ID_LEN],
        });
        let mut maximum_user_id = registration_request();
        maximum_user_id.user.id = vec![0; MAX_USER_HANDLE_LEN];
        for request in [maximum_list, maximum_id, maximum_user_id] {
            let authenticator = SoftwareAuthenticator::new("example.com".into()).unwrap();
            let registration = authenticator.make_credential(&request).unwrap();
            assert_eq!(registration.credential_id, authenticator.credential_id());
            assert!(authenticator.credential.borrow().registered);
            assert_eq!(authenticator.credential.borrow().sign_count, 0);
        }
    }

    #[test]
    fn registration_rejects_credentials_already_used_for_assertions() {
        use super::super::{
            CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
        };

        let authenticator = SoftwareAuthenticator::new("example.com".into()).unwrap();
        let request = WebAuthnGetRequest {
            rp_id: "example.com".into(),
            client_data_hash: [0; 32],
            allow_credentials: vec![CredentialDescriptor {
                id: authenticator.credential_id(),
            }],
            user_verification: UserVerification::Preferred,
        };
        authenticator.get_assertion(&request).unwrap();
        assert!(matches!(
            authenticator.make_credential(&registration_request()),
            Err(crate::Error::AuthenticationRejected)
        ));
        assert!(!authenticator.credential.borrow().registered);
        assert_eq!(authenticator.credential.borrow().sign_count, 1);
    }

    #[test]
    fn realm_fixture_matches_the_seeded_public_credential() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let authenticator = SoftwareAuthenticator::realm_fixture();
        let realm: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/keycloak/realm-export.json")).unwrap();
        let user = realm["users"]
            .as_array()
            .unwrap()
            .iter()
            .find(|user| user["username"] == "passkey-test")
            .unwrap();
        let credential = user["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|credential| credential["type"] == "webauthn")
            .unwrap();
        let data: serde_json::Value =
            serde_json::from_str(credential["credentialData"].as_str().unwrap()).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(data["credentialId"].as_str().unwrap())
                .unwrap(),
            authenticator.credential_id()
        );
        // COSE EC2 / ES256 / P-256 map followed by the two public coordinates.
        let public = authenticator.public_key();
        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        cose.extend_from_slice(&public[1..33]);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(&public[33..]);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(data["credentialPublicKey"].as_str().unwrap())
                .unwrap(),
            cose
        );
        assert_eq!(data["counter"], 0);
        assert_eq!(
            realm["webAuthnPolicyRpId"],
            authenticator.credential.borrow().rp_id
        );
    }

    #[test]
    fn malformed_requests_fail_without_consuming_a_counter() {
        use super::super::{
            CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
        };
        let authenticator = SoftwareAuthenticator::new("example.com".into()).unwrap();
        let id = authenticator.credential_id();
        let valid = || WebAuthnGetRequest {
            rp_id: "example.com".into(),
            client_data_hash: [0; 32],
            allow_credentials: vec![CredentialDescriptor { id: id.clone() }],
            user_verification: UserVerification::Preferred,
        };
        let mut empty_rp = valid();
        empty_rp.rp_id.clear();
        let mut empty_id = valid();
        empty_id
            .allow_credentials
            .push(CredentialDescriptor { id: vec![] });
        let mut oversized_id = valid();
        oversized_id.allow_credentials.push(CredentialDescriptor {
            id: vec![0; MAX_CREDENTIAL_ID_LEN + 1],
        });
        let mut too_many = valid();
        too_many.allow_credentials = (0..=MAX_ALLOW_CREDENTIALS)
            .map(|_| CredentialDescriptor { id: id.clone() })
            .collect();
        for request in [empty_rp, empty_id, oversized_id, too_many] {
            assert!(matches!(
                authenticator.get_assertion(&request),
                Err(crate::Error::AuthenticationRejected)
            ));
            assert_eq!(authenticator.credential.borrow().sign_count, 0);
        }
        let mut boundary = valid();
        boundary.allow_credentials = (0..MAX_ALLOW_CREDENTIALS - 1)
            .map(|_| CredentialDescriptor {
                id: vec![0; MAX_CREDENTIAL_ID_LEN],
            })
            .collect();
        boundary.allow_credentials.push(CredentialDescriptor { id });
        let assertion = authenticator.get_assertion(&boundary).unwrap();
        assert_eq!(&assertion.authenticator_data[33..], &1u32.to_be_bytes());
        assert!(matches!(
            SoftwareAuthenticator::new(String::new()),
            Err(crate::Error::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn test_borrow_conflict_is_an_internal_error() {
        use super::super::{
            CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
        };

        let authenticator = SoftwareAuthenticator::new(String::from("example.com"))
            .expect("authenticator creation should succeed");
        let request = WebAuthnGetRequest {
            rp_id: String::from("example.com"),
            client_data_hash: [0xAB; 32],
            allow_credentials: vec![CredentialDescriptor {
                id: authenticator.credential_id(),
            }],
            user_verification: UserVerification::Preferred,
        };
        let borrowed = authenticator.credential.borrow();
        assert!(matches!(
            authenticator.get_assertion(&request),
            Err(crate::Error::Crypto)
        ));
        assert_eq!(borrowed.sign_count, 0);
        drop(borrowed);

        let assertion = authenticator
            .get_assertion(&request)
            .expect("assertion should succeed after releasing the borrow");
        assert_eq!(
            &assertion.authenticator_data[33..AUTHENTICATOR_DATA_LEN],
            &1u32.to_be_bytes()
        );
    }

    #[test]
    fn test_software_assertion_signing_and_counter() {
        use super::super::{
            CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
        };
        use wolfssl_wolfcrypt::ecc::ECC;

        let authenticator = SoftwareAuthenticator::new(String::from("example.com"))
            .expect("authenticator creation should succeed");
        let mut request = WebAuthnGetRequest {
            rp_id: String::from("example.com"),
            client_data_hash: [0xAB; 32],
            allow_credentials: vec![CredentialDescriptor {
                id: authenticator.credential_id(),
            }],
            user_verification: UserVerification::Preferred,
        };
        // Verify the returned DER signature using a separate ECC verifier with
        // only the public key. No private key is exported for this check.
        let public_key = authenticator.public_key();
        let mut verifier = ECC::import_x963(public_key.as_ref(), None, None)
            .expect("public key import should succeed");
        for count in [1u32, 2] {
            let assertion = authenticator
                .get_assertion(&request)
                .expect("assertion should succeed");
            assert_eq!(assertion.credential_id, authenticator.credential_id());
            assert_eq!(assertion.user_handle, None);
            assert_eq!(
                assertion.authenticator_data,
                assertion_authenticator_data("example.com", false, count)
                    .unwrap()
                    .to_vec()
            );
            let mut message = assertion.authenticator_data.clone();
            message.extend_from_slice(&request.client_data_hash);
            let hash = crate::crypto::sha256(&message).unwrap();
            assert!(verifier.verify_hash(&assertion.signature, &hash).unwrap());
            // Tampering with the client-data portion must invalidate the signature.
            message[AUTHENTICATOR_DATA_LEN] ^= 0xFF;
            let changed_hash = crate::crypto::sha256(&message).unwrap();
            assert!(!verifier
                .verify_hash(&assertion.signature, &changed_hash)
                .unwrap());
        }
        // A rejected request must not consume a counter value.
        request.rp_id = String::from("other.example");
        assert!(matches!(
            authenticator.get_assertion(&request),
            Err(crate::Error::AuthenticationRejected)
        ));
        assert_eq!(authenticator.credential.borrow().sign_count, 2);
        request.rp_id = String::from("example.com");
        // Unsupported verification permits fallback without consuming a counter.
        request.user_verification = UserVerification::Required;
        assert!(matches!(
            authenticator.get_assertion(&request),
            Err(crate::Error::UnsupportedFactor)
        ));
        request.user_verification = UserVerification::Preferred;
        let assertion = authenticator
            .get_assertion(&request)
            .expect("supported verification should still succeed");
        assert_eq!(
            &assertion.authenticator_data[33..AUTHENTICATOR_DATA_LEN],
            &3u32.to_be_bytes()
        );
        // Overflow must also fail without changing the stored counter.
        authenticator.credential.borrow_mut().sign_count = u32::MAX;
        assert!(matches!(
            authenticator.get_assertion(&request),
            Err(crate::Error::AuthenticationRejected)
        ));
        assert_eq!(authenticator.credential.borrow().sign_count, u32::MAX);
    }

    #[test]
    fn test_credential_request_validation() {
        // A valid request binds the stored credential to the same RP and lists
        // its public ID. Preferred verification permits proceeding without UV.
        let credential = InMemoryCredential::new(String::from("example.com"))
            .expect("credential creation should succeed");
        let mut request = super::super::WebAuthnGetRequest {
            rp_id: String::from("example.com"),
            client_data_hash: [0xAB; 32],
            allow_credentials: vec![super::super::CredentialDescriptor {
                id: credential.credential_id.clone(),
            }],
            user_verification: super::super::UserVerification::Preferred,
        };
        assert_eq!(credential.validate_request(&request), Ok(()));

        // Reject a different service even if it supplies the correct credential ID.
        request.rp_id = String::from("other.example");
        assert_eq!(
            credential.validate_request(&request),
            Err(crate::Error::AuthenticationRejected)
        );
        request.rp_id = String::from("example.com");

        // Reject an ID that differs from this credential; restore it afterward
        // so the following assertion isolates the verification requirement.
        request.allow_credentials[0].id[0] ^= 0xFF;
        assert_eq!(
            credential.validate_request(&request),
            Err(crate::Error::AuthenticationRejected)
        );
        request.allow_credentials[0].id = credential.credential_id.clone();
        request.user_verification = super::super::UserVerification::Required;
        assert_eq!(
            credential.validate_request(&request),
            Err(crate::Error::UnsupportedFactor)
        );

        // Discouraged verification is acceptable, but an empty allowed list is
        // outside this initial authenticator's explicit-credential scope.
        request.user_verification = super::super::UserVerification::Discouraged;
        assert_eq!(credential.validate_request(&request), Ok(()));
        request.allow_credentials.clear();
        assert_eq!(
            credential.validate_request(&request),
            Err(crate::Error::AuthenticationRejected)
        );
        // Validation must not advance the signature counter.
        assert_eq!(credential.sign_count, 0);
    }

    #[test]
    fn test_software_authenticator_creation() {
        // Provision the wrapper and retrieve the ID without exposing the key.
        let authenticator = SoftwareAuthenticator::new(String::from("example.com"))
            .expect("software authenticator creation should succeed");
        let mut id = authenticator.credential_id();
        assert_eq!(id.len(), 32);

        // Each call returns a copy of the same stored ID. Changing the copy
        // must not change the authenticator's identity.
        let stored_id = authenticator.credential_id();
        assert_eq!(id, stored_id);
        id[0] ^= 0xFF;
        assert_eq!(authenticator.credential_id(), stored_id);

        // Public key exports are stable owned copies in uncompressed P-256 form.
        let mut public_key = authenticator.public_key();
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);
        let stored_key = public_key.clone();
        public_key[1] ^= 0xFF;
        assert_eq!(authenticator.public_key(), stored_key);
    }

    #[test]
    fn test_in_memory_credential_creation() {
        use signature::{Keypair, SignerMut, Verifier};
        use wolfssl_wolfcrypt::ecdsa::P256Signature;

        // Check provisioning metadata without printing or exporting the private key.
        let mut credential = InMemoryCredential::new(String::from("example.com"))
            .expect("credential creation should succeed");
        assert_eq!(credential.rp_id, "example.com");
        assert_eq!(credential.credential_id.len(), 32);
        assert_eq!(credential.sign_count, 0);

        // The stored key must actually work; field checks alone cannot prove that.
        let public_key = credential.signing_key.verifying_key();
        let message = b"credential key test";
        let signature: P256Signature = credential
            .signing_key
            .try_sign(message)
            .expect("stored key should sign");
        public_key
            .verify(message, &signature)
            .expect("stored key's public key should verify");
        // Signing in this low-level test does not itself update our counter.
        assert_eq!(credential.sign_count, 0);
    }

    #[test]
    fn test_assertion_authenticator_data_rp_id_hash() {
        // This expected SHA-256("example.com") was calculated independently
        // with Python hashlib, not with the helper being tested.
        // The final five bytes are UP alone and a big-endian counter of 1.
        let expected = [
            0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34,
            0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55,
            0x86, 0xCE, 0x19, 0x47, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        let actual = assertion_authenticator_data("example.com", false, 1)
            .expect("RP ID hashing should succeed");
        assert_eq!(actual, expected);

        // Successful verification changes only the UV flag. A zero counter
        // checks the all-zero encoding without changing the known RP hash.
        let mut verified_expected = expected;
        verified_expected[32] = FLAG_UP | FLAG_UV;
        verified_expected[33..AUTHENTICATOR_DATA_LEN].copy_from_slice(&[0, 0, 0, 0]);
        let verified = assertion_authenticator_data("example.com", true, 0)
            .expect("RP ID hashing should succeed");
        assert_eq!(verified, verified_expected);
    }

    #[test]
    fn test_assertion_authenticator_data_layout() {
        // Distinct hash bytes expose misplaced offsets or incomplete copies.
        // This is a layout fixture, not an actual SHA-256 result for an RP ID.
        let rp_id_hash = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        // Bit 0 is UP; bit 2 is UV. Other bits are zero in these examples.
        // Test both user-present-only and user-present-and-verified layouts.
        for flags in [FLAG_UP, FLAG_UP | FLAG_UV] {
            let actual = build_assertion_authenticator_data(&rp_id_hash, flags, 0x01020304);
            // Spell out all 37 expected bytes rather than rebuilding them with
            // the helper's copy/endian operations, so a layout error is visible.
            let expected = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F, flags, 0x01, 0x02, 0x03, 0x04,
            ];
            assert_eq!(actual, expected);
        }
    }
}
