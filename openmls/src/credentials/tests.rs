use crate::test_utils::{test_framework::test_x509::create_test_certificate2, *};

use super::*;

#[test]
fn test_protocol_version() {
    use crate::versions::ProtocolVersion;
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::default();
    let mls10_e = mls10_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(mls10_e[0], mls10_version as u8);
    let default_e = default_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(default_e[0], default_version as u8);
    assert_eq!(mls10_e[0], 1);
    assert_eq!(default_e[0], 1);
}
#[apply(ciphersuites_and_backends)]
fn test_credential(backend: &impl OpenMlsCryptoProvider, ciphersuite: Ciphersuite) {
    let (sk, pk) = SignatureKeypair::new(SignatureScheme::ED25519, backend)
        .unwrap()
        .into_tuple();
    let (cert, sk_cert) = create_test_certificate2(0, pk.clone()).unwrap();
    let credential_bundle = CredentialBundle::new(sk, cert);
    let (sk2, pk3) = SignatureKeypair::new(SignatureScheme::ED25519, backend)
        .unwrap()
        .into_tuple();
    let (cert2, sk_cert2) = create_test_certificate2(2, pk3.clone()).unwrap();
    let credential_bundleb = CredentialBundle::new(sk2, cert2);
    println!("key as pk {:?}", pk.as_slice());
    println!(
        "key as credential  {:?}",
        credential_bundle.credential.signature_key().as_slice()
    );
    println!(
        "{:?}",
        credential_bundle.credential.cert.verify(&sk_cert).unwrap()
    );
    assert!(credential_bundle.credential.cert.verify(&sk_cert).unwrap());
    assert!(pk
        .as_slice()
        .eq_ignore_ascii_case(credential_bundle.credential.signature_key().as_slice()));
    assert!(pk.as_slice().into_iter().eq(credential_bundle
        .credential
        .signature_key()
        .as_slice()
        .into_iter()));
    let mut kpb = crate::prelude::KeyPackageBundle::new(
        &[ciphersuite],
        &credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.")
    .unsigned();

    kpb.add_extension(crate::extensions::Extension::LifeTime(
        crate::extensions::LifetimeExtension::new(60),
    ));
    let kpb = signable::Signable::sign(kpb, backend, &credential_bundle)
        .expect("An unexpected error occurred.");
    let enc = kpb
        .key_package()
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    // Now it's valid.
    let kp = <crate::prelude::KeyPackage as tls_codec::Deserialize>::tls_deserialize(
        &mut enc.as_slice(),
    )
    .expect("An unexpected error occurred.");
    println!("key as pk slice {:?}", pk.as_slice());
    println!(
        "key as credential {:?}",
        kp.credential().signature_key().as_slice()
    );
    println!("{:?}", kp.credential().cert.verify(&sk_cert).unwrap());
    assert!(kp.credential().cert.verify(&sk_cert).unwrap());
    assert!(pk
        .as_slice()
        .eq_ignore_ascii_case(kp.credential().signature_key().as_slice()));
    assert!(pk
        .as_slice()
        .into_iter()
        .eq(kp.credential().signature_key().as_slice().into_iter()));
}

fn test_group(){
    
}