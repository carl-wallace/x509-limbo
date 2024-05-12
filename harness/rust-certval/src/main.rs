use certval::CertificationPathResultsTypes::PathValidationStatus;
use certval::{get_time_of_interest, get_validation_status, populate_5280_pki_environment, set_time_of_interest, CertFile, CertSource, CertVector, CertificationPath, CertificationPathResults, CertificationPathSettings, PDVCertificate, PkiEnvironment, TaSource, set_extended_key_usage, set_enforce_trust_anchor_constraints, enforce_trust_anchor_constraints};
use chrono::{DateTime, Utc};
use limbo_harness_support::{
    load_limbo,
    models::{Feature, LimboResult, PeerKind, Testcase, TestcaseResult, ValidationKind},
};
use std::time::{SystemTime, UNIX_EPOCH};
use certval::PDVExtension::ExtendedKeyUsage;
use x509_cert::{
    certificate::{CertificateInner, Raw},
    der::{DecodePem, Encode},
};
use x509_cert::der::Decode;
use x509_cert::der::oid::db::rfc5280::{ANY_EXTENDED_KEY_USAGE, ID_CE_NAME_CONSTRAINTS, ID_KP_CLIENT_AUTH, ID_KP_CODE_SIGNING, ID_KP_EMAIL_PROTECTION, ID_KP_OCSP_SIGNING, ID_KP_SERVER_AUTH, ID_KP_TIME_STAMPING};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::NameConstraints;
use limbo_harness_support::models::{ActualResult, KnownEkUs};

type Certificate = CertificateInner<Raw>;

fn main() {
    let limbo = load_limbo();

    let mut results = vec![];
    for testcase in &limbo.testcases {
        results.push(evaluate_testcase(testcase));
    }

    let mut unexpected = 0;
    let mut unexpected_but_undetermined_importance = 0;
    for (ii, result) in results.iter().enumerate() {
        let tc = limbo.testcases.get(ii);
        match result.actual_result {
            ActualResult::Success => {
                if tc.unwrap().expected_result.to_string() != "SUCCESS" {
                    println!("Did not get expected result for test case # {ii} - {:?}", tc.unwrap().id);
                    unexpected += 1;
                }
            }
            ActualResult::Failure => {
                if tc.unwrap().expected_result.to_string() != "FAILURE" {
                    println!("Did not get expected result for test case # {ii} - {:?}", tc.unwrap().id);
                    unexpected += 1;
                }
            }
            _ => {}
        }
    }
    println!("Found {unexpected} test cases where expected results were not produced.");

    let result = LimboResult {
        version: 1,
        harness: "certval".into(),
        results,
    };

    serde_json::to_writer_pretty(std::io::stdout(), &result).unwrap();
}

fn has_unsupported_name_constraint(cert: &Certificate) -> bool {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_NAME_CONSTRAINTS {
                let nc = NameConstraints::from_der(ext.extn_value.as_bytes()).unwrap();
                if let Some(perm) = &nc.permitted_subtrees {
                    for gs in perm {
                        match gs.base {
                            GeneralName::IpAddress(_) => return true,
                            GeneralName::OtherName(_) => return true,
                            GeneralName::EdiPartyName(_) => return true,
                            _ => {}
                        }
                    }
                }
                if let Some(excl) = &nc.permitted_subtrees {
                    for gs in excl {
                        match gs.base {
                            GeneralName::IpAddress(_) => return true,
                            GeneralName::OtherName(_) => return true,
                            GeneralName::EdiPartyName(_) => return true,
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    false
}

//fn der_from_pem<B: AsRef<[u8]>>(bytes: B) -> webpki::types::CertificateDer<'static> {
//    let pem = pem::parse(bytes).expect("cert: PEM parse failed");
//    webpki::types::CertificateDer::from(pem.contents()).into_owned()
//}

fn evaluate_testcase(tc: &Testcase) -> TestcaseResult {
    let mut cps = CertificationPathSettings::new();

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

    if tc.extended_key_usage.len() > 0 {
        let mut ekus = vec![];
        for eku in &tc.extended_key_usage {
            match eku {
                KnownEkUs::ServerAuth => ekus.push(ID_KP_SERVER_AUTH.to_string()),
                KnownEkUs::ClientAuth => ekus.push(ID_KP_CLIENT_AUTH.to_string()),
                KnownEkUs::CodeSigning => ekus.push(ID_KP_CODE_SIGNING.to_string()),
                KnownEkUs::EmailProtection => ekus.push(ID_KP_EMAIL_PROTECTION.to_string()),
                KnownEkUs::OcspSigning => ekus.push(ID_KP_OCSP_SIGNING.to_string()),
                KnownEkUs::TimeStamping => ekus.push(ID_KP_TIME_STAMPING.to_string()),
                KnownEkUs::AnyExtendedKeyUsage => ekus.push(ANY_EXTENDED_KEY_USAGE.to_string()),
            }
        }
        set_extended_key_usage(&mut cps, ekus);
    }

    set_enforce_trust_anchor_constraints(&mut cps, true);

    let cert = if let Ok(cert) = Certificate::from_pem(tc.peer_certificate.as_bytes()) {
        cert
    } else {
        return TestcaseResult::fail(tc, "unable to parse cert");
    };
    let mut leaf = PDVCertificate::try_from(cert).unwrap();

    let mut cpr = CertificationPathResults::new();
    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);

    let mut ta_store = TaSource::new();
    for ta in tc.trusted_certs.iter() {
        let cert_ta = Certificate::from_pem(ta.as_bytes()).expect("Read pem file");
        if has_unsupported_name_constraint(&cert_ta) {
            return TestcaseResult::skip(tc, "unsupported name constraint");
        }
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
        if has_unsupported_name_constraint(&cert_ca) {
            return TestcaseResult::skip(tc, "unsupported name constraint");
        }
        cert_store.push(CertFile {
            bytes: cert_ca.to_der().expect("serialize as der"),
            filename: String::new(),
        });
    }
    cert_store.initialize(&cps).unwrap();
    cert_store.find_all_partial_paths(&pe, &cps);

    let time_of_interest = match tc.validation_time {
        Some(toi) => toi.timestamp() as u64,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    set_time_of_interest(&mut cps, time_of_interest);
    //let validation_time = webpki::types::UnixTime::since_unix_epoch(
    //    (tc.validation_time.unwrap_or(Utc::now().into()) - DateTime::UNIX_EPOCH)
    //        .to_std()
    //        .expect("invalid validation time!"),
    //);

    let mut paths: Vec<CertificationPath> = vec![];
    pe.add_certificate_source(Box::new(cert_store.clone()));
    let r = pe
        .get_paths_for_target(&pe, &leaf, &mut paths, 0, time_of_interest)
        .unwrap();

    let mut v = vec![];
    for path in &mut paths {
        let mod_cps = enforce_trust_anchor_constraints(&mut cps, &path.trust_anchor).unwrap();

        let r = match pe.validate_path(&pe, &mod_cps, path, &mut cpr) {
            Ok(()) => match get_validation_status(&cpr) {
                Some(status) => {
                    if certval::PathValidationStatus::Valid == status {
                        return TestcaseResult::success(tc);
                    } else {
                        v.push(status);
                    }
                }
                None => {
                    return TestcaseResult::fail(tc, "no status value returned");
                }
            },
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
