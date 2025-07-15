use base64::{engine::general_purpose, Engine as _};
use coset::{cbor::Value, Algorithm, CborSerializable, ContentType, CoseSign1, Label};
use didx509_sys;
use minicbor::decode::Decoder;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
use serde_json;
use x509_parser::prelude::*;

const LABEL_X5CHAIN: i64 = 33;
const LABEL_CWT: i64 = 15;
const LABEL_ISS: i128 = 1;
const LABEL_SUB: i128 = 2;
const LABEL_IAT: i128 = 6;
const LABEL_SVN: i128 = 7;

#[derive(Debug)]
#[allow(dead_code)]
pub struct CWT {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub iat: Option<i128>,
    pub svn: Option<i128>,
}

#[allow(dead_code)]
pub struct ProtectedHeader {
    pub alg: Option<Algorithm>,
    pub content_type: Option<String>,
    pub cwt: Option<CWT>,
    pub x5chain: Option<Vec<Vec<u8>>>,
}

#[allow(dead_code)]
pub struct UnprotectedHeader {
    pub x5chain: Option<Vec<Vec<u8>>>,
}

#[allow(dead_code)]
pub struct COSEHeaders {
    pub phdr: ProtectedHeader,
    pub uhdr: UnprotectedHeader,
}

fn decode_cwt(cwt_map: &Vec<(Value, Value)>) -> Option<CWT> {
    let mut iss = None;
    let mut sub = None;
    let mut iat = None;
    let mut svn = None;

    for (label, value) in cwt_map.iter() {
        match label {
            Value::Integer(i) => {
                match i128::from(*i) {
                    LABEL_ISS => {
                        iss = match value {
                            Value::Text(s) => Some(s.to_string()),
                            _ => None,
                        };
                    }
                    LABEL_SUB => {
                        sub = match value {
                            Value::Text(s) => Some(s.to_string()),
                            _ => None,
                        };
                    }
                    LABEL_IAT => {
                        iat = match value {
                            Value::Integer(i) => Some(i128::from(*i)),
                            _ => None,
                        };
                    }
                    LABEL_SVN => {
                        svn = match value {
                            Value::Integer(i) => Some(i128::from(*i)),
                            _ => None,
                        };
                    }
                    _ => continue,
                };
            }
            _ => {
                continue;
            }
        }
    }

    Some(CWT { iss, sub, iat, svn })
}

fn decode_cose_headers(cose: &CoseSign1) -> COSEHeaders {
    let mut cwt = None;
    let mut x5chain = None;
    for (label, value) in cose.protected.header.rest.iter() {
        match label {
            Label::Int(LABEL_CWT) => {
                cwt = match value {
                    Value::Map(map) => decode_cwt(map),
                    _ => None,
                };
            }
            Label::Int(LABEL_X5CHAIN) => {
                x5chain = match value {
                    Value::Array(arr) => arr
                        .iter()
                        .map(|v| match v {
                            Value::Bytes(bytes) => {
                                if bytes.is_empty() {
                                    None
                                } else {
                                    Some(bytes.to_vec())
                                }
                            }
                            _ => None,
                        })
                        .collect(),
                    _ => None,
                };
            }
            _ => {
                // Note: Removed print statement for library usage
                continue;
            }
        }
    }

    let phdr = ProtectedHeader {
        alg: cose.protected.header.alg.clone(),
        content_type: match cose.protected.header.content_type.clone() {
            Some(s) => match s {
                ContentType::Text(t) => Some(t.to_string()),
                ContentType::Assigned(a) => match a {
                    // if this is not always json set then we will have match iana::CoapContentFormat
                    _ => None,
                },
            },
            _ => None,
        },
        cwt: cwt,
        x5chain: x5chain,
    };

    let uhdr = UnprotectedHeader { x5chain: None };

    COSEHeaders { phdr, uhdr }
}

fn parse_certificate_chain(
    x5chain: &Option<Vec<Vec<u8>>>,
) -> Result<(Vec<X509Certificate>, String), String> {
    if let Some(chain) = x5chain {
        let mut certificates = Vec::new();
        let mut der_certificates = Vec::new();

        for cert_bytes in chain.iter() {
            match parse_x509_certificate(cert_bytes.as_slice()) {
                Ok((_, cert)) => {
                    certificates.push(cert);
                    der_certificates.push(cert_bytes.to_vec());
                }
                Err(_e) => {
                    if certificates.is_empty() {
                        // If we can't parse certificates, try to handle PEM format
                        return Err("Failed to parse certificate chain as DER, and PEM parsing is not implemented.".to_string());
                    } else {
                        // Warning: Could not parse remaining bytes in certificate chain
                        break;
                    }
                }
            }
        }

        if certificates.is_empty() {
            Err("No valid certificates found in the chain".to_string())
        } else {
            Ok((
                certificates,
                der_certificates
                    .iter()
                    .map(|cert| {
                        let b64 = general_purpose::STANDARD.encode(cert);
                        format!(
                            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                            b64
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            ))
        }
    } else {
        Err("X5Chain is missing".to_string())
    }
}

fn verify_cose_sign1(cose: CoseSign1, cert: &X509Certificate) -> Result<(), String> {
    let spki = &cert.tbs_certificate.subject_pki;
    let pubkey_bytes = &spki.subject_public_key.data;
    assert_eq!(pubkey_bytes[0], 0x04, "expected uncompressed EC point");
    let x = &pubkey_bytes[1..33];
    let y = &pubkey_bytes[33..65];

    let encoded_point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    let verify_key = match VerifyingKey::from_encoded_point(&encoded_point) {
        Ok(key) => key,
        Err(e) => return Err(format!("Failed to create verifying key: {}", e)),
    };

    // TODO: should we support other algorithms?
    match cose.protected.header.alg {
        Some(Algorithm::Assigned(coset::iana::Algorithm::ES256)) => {}
        _ => return Err("Unsupported algorithm".into()),
    }

    match cose.verify_signature(b"", |sig, data| {
        let signature = match Signature::from_slice(&sig) {
            Ok(sig) => sig,
            Err(e) => return Err(format!("Failed to parse signature: {}", e)),
        };
        match verify_key.verify(data, &signature) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Signature verification failed: {}", e)),
        }
    }) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to verify COSE signature: {}", e)),
    }
}

fn verify_statement(signed_statement: &[u8]) -> Result<COSEHeaders, String> {
    if signed_statement.is_empty() {
        return Err("Signed statement is empty".to_string());
    }
    let cose = CoseSign1::from_slice(signed_statement)
        .map_err(|e| format!("Failed to parse COSE: {}", e))?;
    if cose.protected.is_empty() {
        return Err("Protected header is empty".to_string());
    }
    let headers = decode_cose_headers(&cose);
    let cwt = headers
        .phdr
        .cwt
        .as_ref()
        .ok_or("Signed statement protected header must contain CWT_Claims")?;

    let iss = cwt.iss.as_ref().ok_or(
        "Signed statement protected header must contain CWT_Claims with at least an issuer",
    )?;
    if !iss.starts_with("did:x509") {
        return Err("CWT_Claims issuer must start with 'did:x509'".to_string());
    }

    let (certificates, pem_chain) = parse_certificate_chain(&headers.phdr.x5chain)?;
    if certificates.is_empty() {
        return Err("No certificates found in X5Chain".to_string());
    }
    let leaf_cert = &certificates[0];
    if let Err(e) = verify_cose_sign1(cose, leaf_cert) {
        return Err(format!("COSE signature verification failed: {}", e));
    }

    let resolver = didx509_sys::DidX509Resolver::new();
    let did_document_json = resolver
        .resolve(&pem_chain, iss, true)
        .map_err(|e| format!("Failed to resolve DID: {}", e))?;
    let did_document: serde_json::Value = serde_json::from_str(&did_document_json)
        .map_err(|e| format!("Failed to parse DID document JSON: {}", e))?;

    let verification_method = &did_document["verificationMethod"];
    if verification_method.is_null() {
        return Err("Could not find verification method in resolved DID document".to_string());
    }
    let vm = verification_method
        .as_array()
        .ok_or("Verification method in resolved DID document is not an array")?;
    if vm.len() != 1 {
        return Err(
            "Unexpected number of verification methods in resolved DID document".to_string(),
        );
    }
    if &vm[0]["controller"] != iss {
        return Err("Verification method controller does not match CWT issuer".to_string());
    }
    if vm[0]["publicKeyJwk"].is_null() {
        return Err("Verification method does not contain publicKeyJwk".to_string());
    }
    let resolved_jwk = vm[0]["publicKeyJwk"]
        .as_object()
        .ok_or("Verification method publicKeyJwk is not an object")?;

    let resolved_jwk_pem = match resolved_jwk["kty"].as_str() {
        Some("EC") => {
            let x = resolved_jwk["x"]
                .as_str()
                .ok_or("EC JWK missing 'x' field")?;
            let y = resolved_jwk["y"]
                .as_str()
                .ok_or("EC JWK missing 'y' field")?;
            let _curve = resolved_jwk["crv"]
                .as_str()
                .ok_or("EC JWK missing 'crv' field")?;

            let x_bytes = general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| format!("Failed to decode EC JWK 'x' field: {}", e))?;
            let y_bytes = general_purpose::URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|e| format!("Failed to decode EC JWK 'y' field: {}", e))?;

            EncodedPoint::from_affine_coordinates(
                &p256::FieldBytes::from_slice(&x_bytes),
                &p256::FieldBytes::from_slice(&y_bytes),
                false,
            )
        }
        // TODO: support other key types?
        _ => {
            return Err("Unsupported JWK key type, only EC is supported".to_string());
        }
    };

    if resolved_jwk_pem.as_bytes()
        != leaf_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref()
    {
        return Err("Resolved JWK public key does not match signing key PEM".to_string());
    }

    Ok(headers)
}

pub fn validate_scitt_cose_signed_statement(tagged_cose_bytes: &[u8]) -> Result<COSEHeaders, String> {
    let mut dec = Decoder::new(tagged_cose_bytes);

    // SCITT uses tagged statements, as such we expect tag 18 (COSE_Sign1)
    let tag = dec
        .tag()
        .map_err(|e| format!("Error decoding tag: {}", e))?;

    if tag.as_u64() != 18 {
        return Err(format!("Expected tag 18 for COSE_Sign1, got tag {}", tag));
    }

    let start = dec.position();
    dec.skip()
        .map_err(|e| format!("Error skipping COSE_Sign1: {}", e))?;
    let end = dec.position();

    let cose_bytes = &tagged_cose_bytes[start..end];

    match verify_statement(&cose_bytes) {
        Ok(headers) => Ok(headers),
        Err(err) => Err(format!("COSE verification failed: {}", err)),
    }
}