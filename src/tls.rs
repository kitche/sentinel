use rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::TlsAcceptor;
use std::sync::Arc;
use crate::config::TlsConfig;

pub fn create_tls_acceptor(tls_config: &TlsConfig) 
    -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let key = rustls::pki_types::PrivateKeyDer::try_from(
        cert.key_pair.serialize_der()
    )?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);

    let mut server_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)?;

    if tls_config.enable_http2 {
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    } else {
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
