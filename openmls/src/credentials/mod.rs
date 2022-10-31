//! # Credentials
//!
//! A [`Credential`] contains identifying information about the client that
//! created it, as well as a signature public key and the corresponding
//! signature scheme. [`Credential`]s represent clients in MLS groups and are
//! used to authenticate their messages. Each
//! [`KeyPackage`](crate::key_packages::KeyPackage) that is either
//! pre-published, or that represents a client in a group contains a
//! [`Credential`] and is authenticated by it.
//!
//! Clients can create a [`Credential`] by creating a [`CredentialBundle`] which
//! contains the [`Credential`], as well as the corresponding private key
//! material. The [`CredentialBundle`] can in turn be used to generate a
//! [`KeyPackageBundle`](crate::key_packages::KeyPackageBundle).
//!
//! The MLS protocol spec allows the that represents a client in a group to
//! change over time. Concretely, members can issue an Update proposal or a Full
//! Commit to update their [`KeyPackage`](crate::key_packages::KeyPackage), as
//! well as the [`Credential`] in it. The Update has to be authenticated by the
//! signature public key contained in the old [`Credential`].
//!
//! When receiving a credential update from another member, applications must
//! query the Authentication Service to ensure that the new credential is valid.
//!
//! Credentials are specific to a signature scheme, which has to match the
//! ciphersuite of the [`KeyPackage`](crate::key_packages::KeyPackage) that it
//! is embedded in. Clients can use different credentials, potentially with
//! different signature schemes in different groups.
//!
//! There are multiple [`CredentialType`]s, although OpenMLS currently only
//! supports the [`BasicCredential`].

use openmls_traits::{
    types::{CryptoError, SignatureScheme},
    OpenMlsCryptoProvider,
};
use openssl::{nid::Nid, x509::X509};
use serde::{
    de::{Error, Visitor},
    Deserializer, Serializer,
};
use std::fmt;
#[cfg(test)]
use tls_codec::Serialize as TlsSerializeTrait;
use tls_codec::{TlsByteVecU16, VLBytes};

use crate::ciphersuite::*;
mod codec;
#[cfg(test)]
mod tests;
use errors::*;

// Public
pub mod errors;

/// CredentialType.
///
/// This enum contains variants for the different Credential Types.

/// X.509 Certificate.
///
/// This struct contains an X.509 certificate chain.  Note that X.509
/// certificates are not yet supported by OpenMLS.
#[derive(Debug, Clone)]
pub struct Credential {
    /// This struct contains a hash
    hash: TlsByteVecU16,
    /// This struct contains a [`X509`] cert
    pub cert: X509,
}

impl Serialize for Credential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let pem_cert = self.cert.to_pem().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&pem_cert)
    }
}
struct BytesVisitor;

impl<'a> Visitor<'a> for BytesVisitor {
    type Value = &'a [u8];

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a borrowed byte array")
    }

    fn visit_borrowed_bytes<E>(self, v: &'a [u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(v)
    }

    fn visit_borrowed_str<E>(self, v: &'a str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(v.as_bytes())
    }
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let de_bytes = deserializer.deserialize_bytes(BytesVisitor)?;
        let cert = X509::from_pem(de_bytes).map_err(serde::de::Error::custom)?;
        let hash_vec = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .unwrap()
            .to_vec();
        let hash = TlsByteVecU16::new(hash_vec);
        Ok(Credential { hash, cert })
    }
}

impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        self.identity().eq(other.identity())
    }
}

impl Credential {
    /// returns the Identity
    pub fn identity(&self) -> &[u8] {
        println!("id: {:?}", self.hash.as_slice());
        self.hash.as_slice()
    }
    /// returns the [`SignaturePublicKey`]
    pub fn signature_key(&self) -> SignaturePublicKey {
        let vl_bytes = VLBytes::new(
            self.cert
                .public_key()
                .expect("could not extract public key of cert")
                .raw_public_key()
                .expect("could not create raw pk"),
        );
        SignaturePublicKey {
            signature_scheme: SignatureScheme::ED25519,
            value: vl_bytes,
        }
    }
    /// returns the [`SignatureScheme`]
    pub fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
    /// verifies the [`Signature`]
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
        signature: &Signature,
        label: &str,
    ) -> Result<(), CredentialError> {
        self.signature_key()
            .verify_with_label(backend, signature, &SignContent::new(label, payload.into()))
            .map_err(|_| CredentialError::InvalidSignature)
    }
}

/// Credential Bundle.
///
/// This struct contains a [`Credential`] and the private key corresponding to
/// the signature key it contains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq))]
pub struct CredentialBundle {
    credential: Credential,
    signature_private_key: SignaturePrivateKey,
}

impl CredentialBundle {
    /// Creates and returns a new [`CredentialBundle`] of the given
    /// [`CredentialType`] for the given identity and [`SignatureScheme`]. The
    /// corresponding key material is freshly generated.
    ///
    /// Returns an error if the given [`CredentialType`] is not supported.
    pub fn new(signature_private_key: SignaturePrivateKey, cert: X509) -> Self {
        let hash_vec = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .unwrap()
            .to_vec();
        let hash = TlsByteVecU16::new(hash_vec);
        let credential = Credential { hash, cert };
        CredentialBundle {
            credential,
            signature_private_key,
        }
    }

    /// Returns a reference to the [`Credential`].
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Separates the bundle into the [`Credential`] and the [`SignaturePrivateKey`].
    pub fn into_parts(self) -> (Credential, SignaturePrivateKey) {
        (self.credential, self.signature_private_key)
    }

    /// Signs the given message `msg` using the private key of the credential bundle.
    pub(crate) fn sign(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        msg: &[u8],
        label: &str,
    ) -> Result<Signature, CryptoError> {
        self.signature_private_key
            .sign_with_label(backend, &SignContent::new(label, msg.into()))
    }

    /// Returns the key pair of the given credential bundle.
    #[cfg(any(feature = "test-utils", test))]
    pub fn key_pair(&self) -> SignatureKeypair {
        let public_key = self.credential().signature_key();
        let private_key = self.signature_private_key.clone();
        SignatureKeypair::from_parts(public_key, private_key)
    }
}
