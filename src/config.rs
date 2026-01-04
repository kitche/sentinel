use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: Option<TlsConfig>,
    pub proxy: Option<ProxySettings>,
    pub php: Option<PhpConfig>,
    pub waf: Option<WafConfig>,
    pub security: Option<SecurityConfig>,
    pub logging: Option<LoggingConfig>,
    pub vhosts: Option<Vec<VirtualHost>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub http2_port: Option<u16>,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_protocols")]
    pub protocols: Vec<HttpProtocol>,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default)]
    pub hide_server_header: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HttpProtocol {
    Http1,
    Http2,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    #[serde(default = "default_true")]
    pub enable_http2: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxySettings {
    pub backends: Vec<BackendConfig>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_pool_size")]
    pub pool_max_idle_per_host: usize,
    pub routes: Vec<ProxyRoute>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BackendConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyRoute {
    pub path_prefix: String,
    pub backend: String,
    #[serde(default)]
    pub strip_prefix: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PhpConfig {
    #[serde(default = "default_fastcgi_addr")]
    pub fastcgi_addr: String,
    #[serde(default = "default_doc_root")]
    pub document_root: String,
    pub extensions: Vec<String>,
    #[serde(default = "default_php_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WafConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub rules_directory: String,
    #[serde(default)]
    pub log_blocked: bool,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_404_threshold")]
    pub not_found_threshold: u32,
    #[serde(default = "default_404_window")]
    pub not_found_window_secs: u64,
    #[serde(default = "default_pf_table")]
    pub pf_table_name: String,
    #[serde(default)]
    pub block_on_threshold: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_log_path")]
    pub access_log_path: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VirtualHost {
    pub server_name: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub document_root: Option<String>,
    pub proxy: Option<VirtualHostProxy>,
    pub php: Option<PhpConfig>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VirtualHostProxy {
    pub backend: String,
    pub routes: Vec<ProxyRoute>,
}

// Default functions
fn default_worker_threads() -> usize { 4 }
fn default_max_connections() -> usize { 10000 }
fn default_true() -> bool { true }
fn default_timeout() -> u64 { 30 }
fn default_pool_size() -> usize { 10 }
fn default_weight() -> u32 { 1 }
fn default_fastcgi_addr() -> String { "127.0.0.1:9000".to_string() }
fn default_doc_root() -> String { "/var/www/html".to_string() }
fn default_php_timeout() -> u64 { 60 }
fn default_server_name() -> String { "RustWebServer/1.0".to_string() }
fn default_404_threshold() -> u32 { 10 }
fn default_404_window() -> u64 { 60 }
fn default_pf_table() -> String { "webserver_blocklist".to_string() }
fn default_log_path() -> String { "/var/log/webserver/access.log".to_string() }
fn default_log_format() -> String { "combined".to_string() }
fn default_protocols() -> Vec<HttpProtocol> {
    vec![HttpProtocol::Http1, HttpProtocol::Http2]
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&content)?)
    }

    pub fn example_config() -> String {
        let config = Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                http2_port: Some(8443),
                worker_threads: 4,
                max_connections: 10000,
                protocols: vec![HttpProtocol::Http1, HttpProtocol::Http2],
                server_name: "MyServer/1.0".to_string(),
                hide_server_header: false,
            },
            tls: Some(TlsConfig {
                cert_path: "./certs/cert.pem".to_string(),
                key_path: "./certs/key.pem".to_string(),
                enable_http2: true,
            }),
            proxy: Some(ProxySettings {
                backends: vec![
                    BackendConfig {
                        name: "backend1".to_string(),
                        url: "http://localhost:3000".to_string(),
                        weight: 1,
                        enabled: true,
                    },
                ],
                timeout_seconds: 30,
                pool_max_idle_per_host: 10,
                routes: vec![
                    ProxyRoute {
                        path_prefix: "/api/".to_string(),
                        backend: "backend1".to_string(),
                        strip_prefix: false,
                    },
                ],
            }),
            php: Some(PhpConfig {
                fastcgi_addr: "127.0.0.1:9000".to_string(),
                document_root: "/var/www/html".to_string(),
                extensions: vec![".php".to_string()],
                timeout_seconds: 60,
            }),
            waf: Some(WafConfig {
                enabled: true,
                rules_directory: "./waf_rules".to_string(),
                log_blocked: true,
                dry_run: false,
            }),
            security: Some(SecurityConfig {
                enabled: true,
                not_found_threshold: 10,
                not_found_window_secs: 60,
                pf_table_name: "webserver_blocklist".to_string(),
                block_on_threshold: true,
            }),
            logging: Some(LoggingConfig {
                enabled: true,
                access_log_path: "/var/log/webserver/access.log".to_string(),
                format: "combined".to_string(),
            }),
            vhosts: Some(vec![
                VirtualHost {
                    server_name: vec!["example.com".to_string(), "www.example.com".to_string()],
                    aliases: vec![],
                    document_root: Some("/var/www/example.com".to_string()),
                    proxy: None,
                    php: Some(PhpConfig {
                        fastcgi_addr: "127.0.0.1:9000".to_string(),
                        document_root: "/var/www/example.com".to_string(),
                        extensions: vec![".php".to_string()],
                        timeout_seconds: 60,
                    }),
                    enabled: true,
                },
            ]),
        };
        serde_yaml::to_string(&config).unwrap()
    }
}
