//! Signing and verification of the C509 revocation structures.
//!
//! All signed objects (C509 CRL, signed OCSP request, Basic/Simple OCSP
//! response) compute the signature over the **CBOR Sequence** of their TBS
//! group (`encode_tbs()`); `signatureValue` is the raw signature.
//!
//! Signing ([`sign_tbs`]) covers the draft's v1 crypto profile (Ed25519 +
//! ECDSA-secp256r1-SHA256): it signs the raw TBS and returns the signature
//! wrapped as a CBOR byte string — we unwrap it to the raw bytes the structs
//! store. Verification is implemented here for the same profile. (This mirrors
//! the upstream `c509::type2::sign_tbs` for the two profile algorithms; see the
//! standalone-build note in `Cargo.toml`.)

use serde_cbor::Value;

use crate::hashalg;
use crate::lcbor::lcbor_bytes;
use crate::registry;

/// Signing error.
#[derive(Clone, Debug)]
pub enum SignError {
    /// The signer produced something other than a CBOR byte string.
    BadSignerOutput,
    /// No signer is implemented for this signature-algorithm id.
    UnsupportedAlg(i64),
    /// The PKCS#8 PEM private key did not parse for the selected algorithm.
    BadKey,
}

/// Verification error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature did not verify.
    BadSignature,
    /// Key or signature length inconsistent with the algorithm.
    Malformed,
    /// The signature algorithm is not implemented for verification here.
    UnsupportedAlg(i64),
    /// The object is an unsigned variant (e.g. an Error OCSP response).
    NotSigned,
}

/// Sign a TBS sequence, returning the **raw** signature bytes.
///
/// `privkey_pem` is a PKCS#8 PEM private key; `sig_alg` is a C509 signature
/// algorithm id (e.g. [`registry::SIG_ED25519`]).
pub fn sign(tbs: &[u8], privkey_pem: &str, sig_alg: i64) -> Result<Vec<u8>, SignError> {
    let wrapped = sign_tbs(tbs, privkey_pem, sig_alg)?;
    match serde_cbor::from_slice::<Value>(&wrapped) {
        Ok(Value::Bytes(b)) => Ok(b),
        _ => Err(SignError::BadSignerOutput),
    }
}

/// Sign `tbs` with the PKCS#8 PEM key, returning the raw signature wrapped as a
/// CBOR byte string (major type 2) — the same representation the upstream
/// `c509::type2::sign_tbs` produces, for the two v1-profile algorithms.
///
/// - `SIG_ECDSA_SHA256`: secp256r1, deterministic-length `r||s` (64 bytes),
///   over SHA-256(`tbs`).
/// - `SIG_ED25519`: PureEdDSA over `tbs` (64-byte signature).
fn sign_tbs(tbs: &[u8], privkey_pem: &str, sig_alg: i64) -> Result<Vec<u8>, SignError> {
    match sig_alg {
        registry::SIG_ECDSA_SHA256 => {
            use p256::pkcs8::DecodePrivateKey;
            use p256::ecdsa::signature::Signer;
            let sk = p256::ecdsa::SigningKey::from_pkcs8_pem(privkey_pem)
                .map_err(|_| SignError::BadKey)?;
            let sig: p256::ecdsa::Signature = sk.sign(tbs);
            Ok(lcbor_bytes(&sig.to_bytes()))
        }
        registry::SIG_ED25519 => {
            use ed25519_dalek::pkcs8::DecodePrivateKey;
            use ed25519_dalek::Signer;
            let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(privkey_pem)
                .map_err(|_| SignError::BadKey)?;
            Ok(lcbor_bytes(&sk.sign(tbs).to_bytes()))
        }
        other => Err(SignError::UnsupportedAlg(other)),
    }
}

/// Verify a raw signature over `tbs` with `pubkey` under `sig_alg`.
///
/// - `SIG_ED25519`: 32-byte public key, 64-byte signature (PureEdDSA).
/// - `SIG_ECDSA_SHA256`: SEC1 public key (compressed or uncompressed) on
///   secp256r1, 64-byte `r||s` signature, SHA-256 of `tbs`.
pub fn verify(tbs: &[u8], sig: &[u8], pubkey: &[u8], sig_alg: i64)
    -> Result<(), VerifyError>
{
    match sig_alg {
        registry::SIG_ED25519 => verify_ed25519(tbs, sig, pubkey),
        registry::SIG_ECDSA_SHA256 => verify_p256(tbs, sig, pubkey),
        other => Err(VerifyError::UnsupportedAlg(other)),
    }
}

fn verify_ed25519(tbs: &[u8], sig: &[u8], pubkey: &[u8]) -> Result<(), VerifyError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| VerifyError::Malformed)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| VerifyError::Malformed)?;
    let s: [u8; 64] = sig.try_into().map_err(|_| VerifyError::Malformed)?;
    vk.verify(tbs, &Signature::from_bytes(&s))
        .map_err(|_| VerifyError::BadSignature)
}

fn verify_p256(tbs: &[u8], sig: &[u8], pubkey: &[u8]) -> Result<(), VerifyError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| VerifyError::Malformed)?;
    let s = Signature::from_slice(sig).map_err(|_| VerifyError::Malformed)?;
    // The Verifier impl hashes `tbs` with SHA-256 (ecdsa-with-SHA256).
    vk.verify(tbs, &s).map_err(|_| VerifyError::BadSignature)
}

/// Convenience: hash a TBS the way ECDSA-SHA256 verification does (exposed for
/// callers that need the digest, e.g. to cross-check against a hardware verifier).
pub fn ecdsa_sha256_digest(tbs: &[u8]) -> Vec<u8> {
    hashalg::digest(hashalg::SHA_256, tbs).expect("SHA-256 is always available")
}

// --- ergonomic signing/verification on the structures ----------------------

impl crate::crl::C509Crl {
    /// Sign the CRL, setting `signature_value`.
    pub fn sign(&mut self, privkey_pem: &str) -> Result<(), SignError> {
        let sig = sign(&self.encode_tbs(), privkey_pem, self.info.signature_algorithm)?;
        self.signature_value = sig;
        Ok(())
    }

    /// Verify the CRL signature against `pubkey`.
    pub fn verify(&self, pubkey: &[u8]) -> Result<(), VerifyError> {
        verify(&self.encode_tbs(), &self.signature_value, pubkey,
               self.info.signature_algorithm)
    }
}

impl crate::status_list::C509StatusList {
    /// Sign the status list, setting `signature_value`.
    pub fn sign(&mut self, privkey_pem: &str) -> Result<(), SignError> {
        let sig = sign(&self.encode_tbs(), privkey_pem, self.signature_algorithm)?;
        self.signature_value = sig;
        Ok(())
    }

    /// Verify the status-list signature against `pubkey`.
    pub fn verify(&self, pubkey: &[u8]) -> Result<(), VerifyError> {
        verify(&self.encode_tbs(), &self.signature_value, pubkey,
               self.signature_algorithm)
    }
}

impl crate::ocsp_resp::C509OcspResponse {
    /// Verify a signed (Basic/Simple) response against `pubkey`. Returns
    /// `NotSigned` for an Error response.
    pub fn verify(&self, pubkey: &[u8]) -> Result<(), VerifyError> {
        use crate::ocsp_resp::C509OcspResponse::*;
        match self {
            Error { .. } => Err(VerifyError::NotSigned),
            Basic { signature_algorithm, signature_value, .. }
            | Simple { signature_algorithm, signature_value, .. } =>
                verify(&self.encode_tbs(), signature_value, pubkey, *signature_algorithm),
        }
    }
}

impl crate::ocsp_req::C509OcspRequest {
    /// Verify a signed request against `pubkey`. Returns `NotSigned` for the
    /// unsigned request types.
    pub fn verify(&self, pubkey: &[u8]) -> Result<(), VerifyError> {
        use crate::ocsp_req::C509OcspRequest::*;
        match self {
            Signed { signature_algorithm, signature_value, .. } =>
                verify(&self.encode_tbs(), signature_value, pubkey, *signature_algorithm),
            _ => Err(VerifyError::NotSigned),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crl::{C509Crl, CrlInfo};
    use crate::common::Name;

    // Fixed PKCS#8 test keys (generated once; test credentials only).
    const ED_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIC8/cbk33xCU6Pv97ni+qEo9nGD9fIwW19YVnp5XmH0I\n\
-----END PRIVATE KEY-----\n";
    const P256_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTSoZ5vpvAClwvhey\n\
V0+wDfELwTO/5E1lyAgV0z2DJvKhRANCAASm4lb1E6p54XkTxZhrt9opArKq5BgL\n\
LDeB+bVSvgJWg4BROG/yPW9ChJPA4Fsv6/Y+FYkJtaehDVTfkr5w1t/D\n\
-----END PRIVATE KEY-----\n";

    fn ed_pubkey() -> Vec<u8> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        ed25519_dalek::SigningKey::from_pkcs8_pem(ED_PEM)
            .unwrap().verifying_key().to_bytes().to_vec()
    }

    fn p256_pubkey() -> Vec<u8> {
        use p256::pkcs8::DecodePrivateKey;
        p256::ecdsa::SigningKey::from_pkcs8_pem(P256_PEM)
            .unwrap().verifying_key()
            .to_encoded_point(false).as_bytes().to_vec()
    }

    fn sample_crl(sig_alg: i64) -> C509Crl {
        C509Crl {
            info: CrlInfo {
                crl_type: 0,
                signature_algorithm: sig_alg,
                authority_subject: Name::Text("test crlocsp-ca".to_string()),
                authority_key_identifier: Some(vec![0u8; 20]),
                crl_number: 1,
                this_update: 1735776000,
                next_update: Some(1736380800),
                base_crl_number: None,
                crl_extensions: vec![],
            },
            revoked_certs_list: None,
            signature_value: vec![],
        }
    }

    #[test]
    fn crl_sign_verify_round_trip_ed25519() {
        let mut crl = sample_crl(registry::SIG_ED25519);
        crl.sign(ED_PEM).unwrap();
        assert_eq!(crl.signature_value.len(), 64);
        let pk = ed_pubkey();
        assert!(crl.verify(&pk).is_ok());

        // Tampered signature fails.
        let mut bad = crl.clone();
        bad.signature_value[0] ^= 0x01;
        assert_eq!(bad.verify(&pk), Err(VerifyError::BadSignature));

        // Tampered TBS (different crlNumber) fails against the old signature.
        let mut bad2 = crl.clone();
        bad2.info.crl_number = 2;
        assert_eq!(bad2.verify(&pk), Err(VerifyError::BadSignature));
    }

    #[test]
    fn crl_sign_verify_round_trip_p256() {
        let mut crl = sample_crl(registry::SIG_ECDSA_SHA256);
        crl.sign(P256_PEM).unwrap();
        assert_eq!(crl.signature_value.len(), 64);
        let pk = p256_pubkey();
        assert!(crl.verify(&pk).is_ok());

        let mut bad = crl.clone();
        bad.signature_value[10] ^= 0x01;
        assert_eq!(bad.verify(&pk), Err(VerifyError::BadSignature));
    }
}
