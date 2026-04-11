use rustls::ServerConfig as TlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio_rustls::TlsAcceptor;
use std::sync::Arc;
use crate::config::TlsConfig;

pub fn create_tls_acceptor(tls_config: &TlsConfig) 
    -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read(&tls_config.cert_path)?;
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&cert_pem).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err("No certificates found in cert_path".into());
    }

    let key_pem = std::fs::read(&tls_config.key_path)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)?;

    let mut server_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    if tls_config.enable_http2 {
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    } else {
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
