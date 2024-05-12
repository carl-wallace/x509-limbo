use std::time::{SystemTime, UNIX_EPOCH};
use certval::{populate_5280_pki_environment, CertFile, CertVector, CertificationPath, CertificationPathResults, CertificationPathSettings, PDVCertificate, PkiEnvironment, TaSource, CertSource, get_time_of_interest, get_validation_status};
use certval::CertificationPathResultsTypes::PathValidationStatus;
use chrono::{DateTime, Utc};
use limbo_harness_support::{
    load_limbo,
    models::{Feature, LimboResult, PeerKind, Testcase, TestcaseResult, ValidationKind},
};
use x509_cert::{
    der::{DecodePem, Encode},
    Certificate,
};

fn main() {
    let limbo = load_limbo();

    let mut results = vec![];
    for testcase in limbo.testcases {
        results.push(evaluate_testcase(&testcase));
    }

    let result = LimboResult {
        version: 1,
        harness: "certval".into(),
        results,
    };

    serde_json::to_writer_pretty(std::io::stdout(), &result).unwrap();
}

//fn der_from_pem<B: AsRef<[u8]>>(bytes: B) -> webpki::types::CertificateDer<'static> {
//    let pem = pem::parse(bytes).expect("cert: PEM parse failed");
//    webpki::types::CertificateDer::from(pem.contents()).into_owned()
//}

fn evaluate_testcase(tc: &Testcase) -> TestcaseResult {
    let cps = CertificationPathSettings::new();

    if tc.features.contains(&Feature::MaxChainDepth) {
        return TestcaseResult::skip(
            tc,
            "max-chain-depth testcases are not supported by this API",
        );
    }

    if !matches!(tc.validation_kind, ValidationKind::Server) {
        return TestcaseResult::skip(tc, "non-SERVER testcases not supported yet");
    }

    if !tc.signature_algorithms.is_empty() {
        return TestcaseResult::skip(tc, "signature_algorithms not supported yet");
    }

    if !tc.key_usage.is_empty() {
        return TestcaseResult::skip(tc, "key_usage not supported yet");
    }

    let mut leaf = PDVCertificate::try_from(
        Certificate::from_pem(tc.peer_certificate.as_bytes()).expect("parse leaf pem"),
    )
    .unwrap();

    let mut cpr = CertificationPathResults::new();
    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);

    let mut ta_store = TaSource::new();
    for ta in tc.trusted_certs.iter() {
        let cert_ta = Certificate::from_pem(ta.as_bytes()).expect("Read pem file");
        ta_store.push(CertFile {
            bytes: cert_ta.to_der().expect("serialize as der"),
            filename: String::new(),
        });
    }
    ta_store.initialize().unwrap();
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));

    let mut cert_store = CertSource::new();
    for ca in tc.untrusted_intermediates.iter() {
        let cert_ca = Certificate::from_pem(ca.as_bytes()).expect("Read pem file");
        cert_store.push(CertFile {
            bytes: cert_ca.to_der().expect("serialize as der"),
            filename: String::new(),
        });
    }
    cert_store.initialize(&cps).unwrap();
    cert_store.find_all_partial_paths(&pe, &cps);

    let time_of_interest = match tc.validation_time {
        Some(toi) => toi.timestamp() as u64,
        None => SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    };
    //let validation_time = webpki::types::UnixTime::since_unix_epoch(
    //    (tc.validation_time.unwrap_or(Utc::now().into()) - DateTime::UNIX_EPOCH)
    //        .to_std()
    //        .expect("invalid validation time!"),
    //);

    let mut paths: Vec<CertificationPath> = vec![];
    pe.add_certificate_source(Box::new(cert_store.clone()));
    let r = pe.get_paths_for_target(&pe, &leaf, &mut paths, 0, time_of_interest).unwrap();


    let mut v = vec![];
    for path in &mut paths {
        let r = match pe.validate_path(&pe, &cps, path, &mut cpr) {
            Ok(()) => {
                match get_validation_status(&cpr) {
                    Some(status) => {
                        if certval::PathValidationStatus::Valid == status {
                            return TestcaseResult::success(tc)
                        }
                        else {
                            v.push(status);
                        }
                    }
                    None => {
                        return TestcaseResult::fail(tc, "no status value returned");
                    }
                }
            }
            Err(e) => {
                return TestcaseResult::fail(tc, &format!("validate_path failed with {e:?}"));
            }
        };
    }
    TestcaseResult::fail(tc, &format!("{:?}", v))


    //let Ok(trust_anchors) = trust_anchor_ders
    //    .iter()
    //    .map(|ta| webpki::anchor_from_trusted_cert(ta.into()))
    //    .collect::<Result<Vec<_>, _>>()
    //else {
    //    return TestcaseResult::fail(tc, "trusted certs: trust anchor extraction failed");
    //};

    //let validation_time = webpki::types::UnixTime::since_unix_epoch(
    //    (tc.validation_time.unwrap_or(Utc::now().into()) - DateTime::UNIX_EPOCH)
    //        .to_std()
    //        .expect("invalid validation time!"),
    //);

    //let sig_algs = &[
    //    ring::ECDSA_P256_SHA256,
    //    ring::ECDSA_P384_SHA384,
    //    ring::RSA_PKCS1_2048_8192_SHA256,
    //    ring::RSA_PKCS1_2048_8192_SHA384,
    //    ring::RSA_PKCS1_2048_8192_SHA512,
    //    ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    //    ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    //    ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    //];

    //if let Err(e) = leaf.verify_for_usage(
    //    sig_algs,
    //    &trust_anchors,
    //    &intermediates[..],
    //    validation_time,
    //    webpki::KeyUsage::server_auth(),
    //    None,
    //    None,
    //) {
    //    return TestcaseResult::fail(tc, &e.to_string());
    //}

    //let subject_name = match &tc.expected_peer_name {
    //    None => return TestcaseResult::skip(tc, "implementation requires peer names"),
    //    Some(pn) => match pn.kind {
    //        PeerKind::Dns => webpki::types::ServerName::DnsName(
    //            webpki::types::DnsName::try_from(pn.value.as_str())
    //                .expect(&format!("invalid expected DNS name: {}", &pn.value)),
    //        ),
    //        PeerKind::Ip => {
    //            let addr = pn.value.as_str().try_into().unwrap();
    //            webpki::types::ServerName::IpAddress(addr)
    //        }
    //        _ => return TestcaseResult::skip(tc, "implementation requires DNS or IP peer names"),
    //    },
    //};

    //if let Err(_) = leaf.verify_is_valid_for_subject_name(&subject_name) {
    //    TestcaseResult::fail(tc, "subject name validation failed")
    //} else {
    //    TestcaseResult::success(tc)
    //}
    //TestcaseResult::fail(tc, "wip")
}
