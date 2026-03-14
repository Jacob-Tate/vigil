use std::{net::ToSocketAddrs, sync::Arc};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, Error as RustlsError, ProtocolVersion, SignatureScheme,
};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::types::CertChainEntry;

const SSL_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Intermediate result of an SSL check — parsed before storage.
pub struct SslCheckResult {
    pub error: Option<String>,
    pub tls_version: Option<String>,
    pub subject_cn: Option<String>,
    pub subject_o: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_o: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub days_remaining: Option<i64>,
    pub fingerprint_sha256: Option<String>,
    pub serial_number: Option<String>,
    pub sans: Vec<String>,
    pub chain: Vec<CertChainEntry>,
    pub pem_chain: String,
}

impl SslCheckResult {
    fn error(msg: impl Into<String>) -> Self {
        Self {
            error: Some(msg.into()),
            tls_version: None,
            subject_cn: None,
            subject_o: None,
            issuer_cn: None,
            issuer_o: None,
            valid_from: None,
            valid_to: None,
            days_remaining: None,
            fingerprint_sha256: None,
            serial_number: None,
            sans: Vec::new(),
            chain: Vec::new(),
            pem_chain: String::new(),
        }
    }
}

/// Custom cert verifier: accepts all certificates but still verifies TLS signatures.
/// This mirrors Node.js's `rejectUnauthorized: false` — we want to connect to expired
/// or self-signed certs so we can inspect and alert on them.
#[derive(Debug)]
struct AcceptAllCerts(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AcceptAllCerts {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// Convert a unix timestamp (seconds) to an RFC3339 string.
fn format_unix_secs(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

fn fingerprint_hex(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if i == 0 {
                format!("{:02X}", b)
            } else {
                format!(":{:02X}", b)
            }
        })
        .collect()
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let wrapped: String = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        wrapped
    )
}

fn parse_cert_chain(certs: &[CertificateDer<'_>]) -> (Vec<CertChainEntry>, String) {
    let mut chain_entries = Vec::new();
    let mut pem_parts = Vec::new();

    for cert_der in certs {
        let der_bytes = cert_der.as_ref();
        pem_parts.push(der_to_pem(der_bytes));

        let fp = fingerprint_hex(der_bytes);

        if let Ok((_, parsed)) = parse_x509_certificate(der_bytes) {
            let subject_cn = parsed
                .subject()
                .iter_common_name()
                .next()
                .and_then(|a| a.as_str().ok())
                .map(|s| s.to_string());
            let subject_o = parsed
                .subject()
                .iter_organization()
                .next()
                .and_then(|a| a.as_str().ok())
                .map(|s| s.to_string());
            let issuer_cn = parsed
                .issuer()
                .iter_common_name()
                .next()
                .and_then(|a| a.as_str().ok())
                .map(|s| s.to_string());
            let issuer_o = parsed
                .issuer()
                .iter_organization()
                .next()
                .and_then(|a| a.as_str().ok())
                .map(|s| s.to_string());

            let valid_from = format_unix_secs(parsed.validity().not_before.to_datetime().unix_timestamp());
            let valid_to = format_unix_secs(parsed.validity().not_after.to_datetime().unix_timestamp());

            let serial = parsed.raw_serial_as_string();
            let is_self_signed = parsed.is_ca()
                && parsed.issuer() == parsed.subject();

            chain_entries.push(CertChainEntry {
                subject_cn,
                subject_o,
                issuer_cn,
                issuer_o,
                valid_from,
                valid_to,
                fingerprint_sha256: fp,
                serial_number: serial,
                is_self_signed,
            });
        } else {
            // Couldn't parse — still include a minimal entry with the fingerprint
            chain_entries.push(CertChainEntry {
                subject_cn: None,
                subject_o: None,
                issuer_cn: None,
                issuer_o: None,
                valid_from: String::new(),
                valid_to: String::new(),
                fingerprint_sha256: fp,
                serial_number: String::new(),
                is_self_signed: false,
            });
        }
    }

    let pem_chain = pem_parts.join("\n");
    (chain_entries, pem_chain)
}

fn extract_sans(cert_der: &[u8]) -> Vec<String> {
    let Ok((_, parsed)) = parse_x509_certificate(cert_der) else {
        return Vec::new();
    };

    let Ok(Some(san_ext)) = parsed.get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME) else {
        return Vec::new();
    };

    if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
        san.general_names
            .iter()
            .map(|name| match name {
                GeneralName::DNSName(s) => format!("DNS:{}", s),
                GeneralName::IPAddress(bytes) => {
                    if bytes.len() == 4 {
                        format!("IP:{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
                    } else {
                        format!("IP:{}", hex::encode(bytes))
                    }
                }
                GeneralName::RFC822Name(s) => format!("email:{}", s),
                GeneralName::URI(s) => format!("URI:{}", s),
                _ => format!("{:?}", name),
            })
            .collect()
    } else {
        Vec::new()
    }
}

pub async fn check_ssl_certificate(host: &str, port: u16) -> SslCheckResult {
    let algs = rustls::crypto::ring::default_provider()
        .signature_verification_algorithms;
    let verifier = Arc::new(AcceptAllCerts(algs));

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => return SslCheckResult::error(format!("Invalid hostname '{}': {}", host, e)),
    };

    let addr_str = format!("{}:{}", host, port);
    let addr = match addr_str.to_socket_addrs().and_then(|mut a| {
        a.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))
    }) {
        Ok(a) => a,
        Err(e) => return SslCheckResult::error(format!("DNS resolution failed: {}", e)),
    };

    let connect_future = TcpStream::connect(addr);
    let tcp_stream = match tokio::time::timeout(
        std::time::Duration::from_millis(SSL_CONNECT_TIMEOUT_MS),
        connect_future,
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return SslCheckResult::error(format!("TCP connect failed: {}", e)),
        Err(_) => return SslCheckResult::error("Connection timeout"),
    };

    let tls_stream = match tokio::time::timeout(
        std::time::Duration::from_millis(SSL_CONNECT_TIMEOUT_MS),
        connector.connect(server_name, tcp_stream),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return SslCheckResult::error(format!("TLS handshake failed: {}", e)),
        Err(_) => return SslCheckResult::error("TLS handshake timeout"),
    };

    let (_, client_conn) = tls_stream.get_ref();

    let tls_version = client_conn.protocol_version().map(|v| match v {
        ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        other => format!("{:?}", other),
    });

    let certs = match client_conn.peer_certificates() {
        Some(c) if !c.is_empty() => c.to_vec(),
        _ => return SslCheckResult::error("No certificate returned"),
    };

    // The leaf cert is first
    let leaf_der = certs[0].as_ref();
    let (chain, pem_chain) = parse_cert_chain(&certs);

    let fingerprint_sha256 = Some(fingerprint_hex(leaf_der));
    let sans = extract_sans(leaf_der);

    let leaf_entry = chain.first();
    let subject_cn = leaf_entry.and_then(|e| e.subject_cn.clone());
    let subject_o = leaf_entry.and_then(|e| e.subject_o.clone());
    let issuer_cn = leaf_entry.and_then(|e| e.issuer_cn.clone());
    let issuer_o = leaf_entry.and_then(|e| e.issuer_o.clone());
    let valid_from = leaf_entry.map(|e| e.valid_from.clone());
    let valid_to_str = leaf_entry.map(|e| e.valid_to.clone());
    let serial_number = leaf_entry.map(|e| e.serial_number.clone());

    let days_remaining = valid_to_str.as_deref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| {
                let now = chrono::Utc::now();
                let diff = dt.signed_duration_since(now);
                diff.num_days()
            })
    });

    SslCheckResult {
        error: None,
        tls_version,
        subject_cn,
        subject_o,
        issuer_cn,
        issuer_o,
        valid_from,
        valid_to: valid_to_str,
        days_remaining,
        fingerprint_sha256,
        serial_number,
        sans,
        chain,
        pem_chain,
    }
}
