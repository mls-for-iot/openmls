//! Serialization for key store objects.

use std::clone;

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
        let bytes = (*ksv).to_vec().clone();
        Ok(KeyPackageBundle::tls_deserialize(&mut bytes.as_slice()).unwrap())
    }
}

impl FromKeyStoreValue for CredentialBundle {
    type Error = LibraryError;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv).map_err(|_| LibraryError::custom("Invalid credential bundle."))
    }
}

impl ToKeyStoreValue for KeyPackageBundle {
    type Error = LibraryError;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.tls_serialize_detached().unwrap())
    }
}

impl ToKeyStoreValue for CredentialBundle {
    type Error = LibraryError;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self)
            .map_err(|_| LibraryError::custom("Error serializing key package bundle."))
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
        serde_json::to_vec(self).map_err(|_| LibraryError::custom("Error serializing PSK bundle."))
    }
}
