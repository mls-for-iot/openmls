#[cfg(any(feature = "test-utils", test))]
pub(crate) fn build_x509_name(
    country: &str,
    state: &str,
    domain: &str,
    organization: &str,
    common_name: &str,
) -> Result<X509Name, ErrorStack> {
    let mut x509_name = openssl::x509::X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", country)?;
    x509_name.append_entry_by_text("ST", state)?;
    x509_name.append_entry_by_text("O", organization)?;
    x509_name.append_entry_by_text("OU", domain)?;
    x509_name.append_entry_by_text("CN", common_name)?;
    Ok(x509_name.build())
}
use crate::prelude_test::SignaturePublicKey;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Name, X509,
    },
};

#[cfg(any(feature = "test-utils", test))]
pub fn create_test_certificate(
    serial_num: u32,
    pk: SignaturePublicKey,
) -> Result<X509, ErrorStack> {
    use openssl::pkey::Id;

    let sk = PKey::generate_ed25519().expect("failed to generate ed25519 sk");
    let mut builder = X509::builder()?;
    builder.set_version(0)?;
    let issuer_name = build_x509_name("DE", "SH", "AUTH-DEPARTMENT", "TEStORG", "TEStISSUER")?;
    builder.set_issuer_name(&issuer_name)?;
    let bn_serial_num = BigNum::from_u32(serial_num)?;
    let asn1_int = Asn1Integer::from_bn(&bn_serial_num)?;
    builder.set_serial_number(&asn1_int)?;
    let openssl_pk = openssl::pkey::PKey::public_key_from_raw_bytes(pk.as_slice(), Id::ED25519)?;
    builder.set_pubkey(&openssl_pk)?;
    let subject_name = build_x509_name("DE", "SH", "TEST", "TEStORG", "HEATSENSOR")?;
    builder.set_subject_name(&subject_name)?;
    let end_date = Asn1Time::days_from_now(30)?;
    builder.set_not_after(&end_date)?;
    let start_date = Asn1Time::days_from_now(0)?;
    builder.set_not_before(&start_date)?;
    let bc = BasicConstraints::new().pathlen(2).build()?;
    builder.append_extension(bc)?;
    let key_usage = KeyUsage::new()
        .digital_signature()
        .non_repudiation()
        .build()?;
    builder.append_extension(key_usage)?;
    builder.sign(&sk, MessageDigest::null())?;
    Ok(builder.build())
}

#[cfg(any(feature = "test-utils", test))]
pub fn create_test_certificate2(
    serial_num: u32,
    pk: SignaturePublicKey,
) -> Result<(X509, PKey<Private>), ErrorStack> {
    use openssl::pkey::Id;

    let sk = PKey::generate_ed25519().expect("failed to generate ed25519 sk");
    let mut builder = X509::builder()?;
    builder.set_version(0)?;
    let issuer_name = build_x509_name("DE", "SH", "AUTH-DEPARTMENT", "TEStORG", "TEStISSUER")?;
    builder.set_issuer_name(&issuer_name)?;
    let bn_serial_num = BigNum::from_u32(serial_num)?;
    let asn1_int = Asn1Integer::from_bn(&bn_serial_num)?;
    builder.set_serial_number(&asn1_int)?;
    let openssl_pk = openssl::pkey::PKey::public_key_from_raw_bytes(pk.as_slice(), Id::ED25519)?;
    builder.set_pubkey(&openssl_pk)?;
    let subject_name = build_x509_name("DE", "SH", "TEST", "TEStORG", "HEATSENSOR")?;
    builder.set_subject_name(&subject_name)?;
    let end_date = Asn1Time::days_from_now(30)?;
    builder.set_not_after(&end_date)?;
    let start_date = Asn1Time::days_from_now(0)?;
    builder.set_not_before(&start_date)?;
    let bc = BasicConstraints::new().pathlen(2).build()?;
    builder.append_extension(bc)?;
    let key_usage = KeyUsage::new()
        .digital_signature()
        .non_repudiation()
        .build()?;
    builder.append_extension(key_usage)?;
    builder.sign(&sk, MessageDigest::null())?;
    Ok((builder.build(), sk))
}
