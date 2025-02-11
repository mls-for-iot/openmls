#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::{prelude::*, test_utils::test_framework::test_x509::create_test_certificate};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};

fn criterion_kp_bundle(c: &mut Criterion, backend: &impl OpenMlsCryptoProvider) {
    for &ciphersuite in backend.crypto().supported_ciphersuites().iter() {
        c.bench_function(
            &format!(
                "KeyPackage create bundle with ciphersuite: {:?}",
                ciphersuite
            ),
            move |b| {
                b.iter_with_setup(
                    || {
                        let (sk, pk) = SignatureKeypair::new(SignatureScheme::ED25519, backend)
                            .unwrap()
                            .into_tuple();
                        let cert = create_test_certificate(0, pk).unwrap();
                        CredentialBundle::new(sk, cert)
                    },
                    |credential_bundle: CredentialBundle| {
                        KeyPackageBundle::new(
                            &[ciphersuite],
                            &credential_bundle,
                            backend,
                            Vec::new(),
                        )
                        .expect("An unexpected error occurred.");
                    },
                );
            },
        );
    }
}

fn kp_bundle_rust_crypto(c: &mut Criterion) {
    let backend = &OpenMlsRustCrypto::default();
    println!("Backend: RustCrypto");
    criterion_kp_bundle(c, backend);
}

#[cfg(feature = "evercrypt")]
fn kp_bundle_evercrypt(c: &mut Criterion) {
    use openmls_evercrypt::OpenMlsEvercrypt;
    let backend = &OpenMlsEvercrypt::default();
    println!("Backend: Evercrypt");
    criterion_kp_bundle(c, backend);
}

fn criterion_benchmark(c: &mut Criterion) {
    kp_bundle_rust_crypto(c);
    #[cfg(feature = "evercrypt")]
    kp_bundle_evercrypt(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
