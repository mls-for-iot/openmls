//! Serialization for key store objects.
use crate::{
    credentials::CredentialBundle, key_packages::KeyPackageBundle, prelude::LibraryError,
    schedule::psk::PskBundle,
};

use openmls_traits::key_store::{FromKeyStoreValue, ToKeyStoreValue};
use tls_codec::{Deserialize, Serialize};

// === OpenMLS Key Store Types

impl FromKeyStoreValue for KeyPackageBundle {
    type Error = LibraryError;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        let bytes = (*ksv).to_vec();
        KeyPackageBundle::tls_deserialize(&mut bytes.as_slice())
            .map_err(|_| LibraryError::custom("Invalid Key package bundle."))
    }
}

impl FromKeyStoreValue for CredentialBundle {
    type Error = LibraryError;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        let bytes = (*ksv).to_vec();
        CredentialBundle::tls_deserialize(&mut bytes.as_slice())
            .map_err(|_| LibraryError::custom("Invalid Credential bundle."))
    }
}

impl ToKeyStoreValue for KeyPackageBundle {
    type Error = LibraryError;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        //unwrap wegmachen
        self.tls_serialize_detached()
            .map_err(|_| LibraryError::custom("Error serializing Key Package bundle."))
    }
}

impl ToKeyStoreValue for CredentialBundle {
    type Error = LibraryError;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        self.tls_serialize_detached()
            .map_err(|_| LibraryError::custom("Error serializing Credential bundle."))
    }
}

// PSKs

impl FromKeyStoreValue for PskBundle {
    type Error = LibraryError;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv).map_err(|_| LibraryError::custom("Invalid PSK bundle."))
    }
}

impl ToKeyStoreValue for PskBundle {
    type Error = LibraryError;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        self.tls_serialize_detached()
            .map_err(|_| LibraryError::custom("Error serializing PSK bundle."))
    }
}
