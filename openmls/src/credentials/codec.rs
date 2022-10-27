use std::io::Read;

use tls_codec::Size;

use super::*;

impl tls_codec::Size for Credential {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        let pem_cert = self.cert.to_pem();
        match pem_cert {
            Ok(res) => res.len(),
            Err(_) => 0,
        }
    }
}

impl tls_codec::Serialize for Credential {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let pem_cert = self
            .cert
            .to_pem()
            .map_err(|_| tls_codec::Error::InvalidInput)?;
        let vec = TlsByteVecU16::new(pem_cert);
        vec.tls_serialize(writer)
    }

    fn tls_serialize_detached(&self) -> Result<Vec<u8>, tls_codec::Error> {
        let mut buffer = Vec::with_capacity(self.tls_serialized_len());
        let written = self.tls_serialize(&mut buffer)?;
        debug_assert_eq!(
            written,
            buffer.len(),
            "Expected that {} bytes were written but the output holds {} bytes",
            written,
            buffer.len()
        );

        if written != buffer.len() {
            Err(tls_codec::Error::EncodingError(format!(
                "Expected that {} bytes were written but the output holds {} bytes",
                written,
                buffer.len()
            )))
        } else {
            Ok(buffer)
        }
    }
}

impl tls_codec::Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let val = TlsByteVecU16::tls_deserialize(bytes)?;
        let cert = X509::from_pem(val.as_slice()).map_err(|_| tls_codec::Error::InvalidInput)?;
        Ok(Credential { cert })
    }
}
