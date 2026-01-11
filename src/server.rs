use std::convert::Infallible;
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use hyper::{Request, Response, body::Incoming, Method, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use tokio::net::TcpListener;
use http_body_util::{Full, BodyExt, combinators::BoxBody};
use hyper::body::Bytes;
use tokio_rustls::TlsAcceptor;
use crate::config::{Config, HttpProtocol};
use crate::proxy::ProxyConfig;

pub trait RequestHandler {
    fn handle_request(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> impl std::future::Future<Output = Result<Response<BoxBody<Bytes, Infallible>>, Infallible>> + Send;
}

pub struct WebServer {
    config: Arc<Config>,
    proxy_config: Option<Arc<ProxyConfig>>,
    client: Client<HttpConnector, Incoming>,
    tls_acceptor: Option<TlsAcceptor>,
    rate_limiter: Option<Arc<crate::security::RateLimiter>>,
    pf_blocker: Option<Arc<crate::security::PfBlocker>>,
    php_client: Option<Arc<crate::php::FastCgiClient>>,
    access_logger: Option<Arc<crate::logging::AccessLogger>>,
    vhost_matcher: Option<Arc<crate::vhost::VirtualHostMatcher>>,
}

impl WebServer {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let timeout = config.proxy.as_ref()
            .map(|p| p.timeout_seconds)
            .unwrap_or(30);
        let pool_size = config.proxy.as_ref()
            .map(|p| p.pool_max_idle_per_host)
            .unwrap_or(10);

        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(timeout)));
        connector.enforce_http(false);

        let client = Client::builder(hyper_util::rt::TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(pool_size)
            .build(connector);

        let proxy_config = config.proxy.as_ref()
            .map(|p| Arc::new(ProxyConfig::new(p.clone())));

        let tls_acceptor = if let Some(tls_config) = &config.tls {
            Some(crate::tls::create_tls_acceptor(tls_config)?)
        } else {
            None
        };

        // Setup security features
        let (rate_limiter, pf_blocker) = if let Some(ref sec_config) = config.security {
            if sec_config.enabled {
                let limiter = Arc::new(crate::security::RateLimiter::new(
                    sec_config.not_found_threshold,
                    sec_config.not_found_window_secs,
                ));
                
                // Start cleanup task
                limiter.clone().start_cleanup_task();

                let blocker = if sec_config.block_on_threshold {
                    Some(Arc::new(crate::security::PfBlocker::new(
                        sec_config.pf_table_name.clone()
                    )))
                } else {
                    None
                };

                (Some(limiter), blocker)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Setup PHP FastCGI client (global fallback)
        let php_client = if let Some(ref php_config) = config.php {
            match crate::php::FastCgiClient::new(
                php_config.fastcgi_addr.clone(),
                php_config.document_root.clone(),
            ) {
                Ok(client) => Some(Arc::new(client)),
                Err(e) => {
                    eprintln!("⚠️  Failed to initialize PHP client: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Setup access logger
        let access_logger = if let Some(ref log_config) = config.logging {
            if log_config.enabled {
                use std::path::PathBuf;
                let log_path = PathBuf::from(&log_config.access_log_path);
                
                // Create parent directory if it doesn't exist
                if let Some(parent) = log_path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        eprintln!("⚠️  Failed to create log directory: {}", e);
                    }
                }

                let format = match log_config.format.as_str() {
                    "json" => crate::logging::access_log::LogFormat::Json,
                    "common" => crate::logging::access_log::LogFormat::Common,
                    _ => crate::logging::access_log::LogFormat::Combined,
                };

                Some(Arc::new(crate::logging::AccessLogger::new(log_path, format)))
            } else {
                None
            }
        } else {
            None
        };

        // Setup virtual hosts
        let vhost_matcher = if let Some(ref vhosts) = config.vhosts {
            if !vhosts.is_empty() {
                Some(Arc::new(crate::vhost::VirtualHostMatcher::new(vhosts.clone())))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config: Arc::new(config),
            proxy_config,
            client,
            tls_acceptor,
            rate_limiter,
            pf_blocker,
            php_client,
            access_logger,
            vhost_matcher,
        })
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let server = Arc::new(self);
        let mut handles = vec![];

        if server.config.server.protocols.contains(&HttpProtocol::Http1) 
            || server.config.server.protocols.contains(&HttpProtocol::Http2) {
            let s = Arc::clone(&server);
            let handle = tokio::spawn(async move {
                if let Err(e) = s.run_http1_http2().await {
                    eprintln!("HTTP/1-2 server error: {}", e);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await?;
        }

        Ok(())
    }

    async fn run_http1_http2(&self) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = format!("{}:{}",
        self.config.server.host,
        self.config.server.http2_port.unwrap_or(self.config.server.port)
    ).parse()?;
    
    let listener = TcpListener::bind(addr).await?;
    println!("🚀 Server running on {}", addr);
    self.print_server_info();
    
    loop {
        // Handle connection accept errors gracefully
        let (stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                // Log the error but don't crash the server
                eprintln!("Failed to accept connection: {} (continuing...)", e);
                continue;
            }
        };
        
        let server = Arc::new(self.clone_refs());
        
        tokio::spawn(async move {
            if let Some(ref acceptor) = server.tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let protocol = {
                            let (_, session) = tls_stream.get_ref();
                            session.alpn_protocol()
                                .and_then(|p| std::str::from_utf8(p).ok())
                                .map(|s| s.to_string())
                        };
                        
                        let io = TokioIo::new(tls_stream);
                        
                        match protocol.as_deref() {
                            Some("h2") => {
                                println!("HTTP/2 from {}", remote_addr);
                                let _ = crate::protocol::http2::serve_connection(
                                    io, server, remote_addr
                                ).await;
                            }
                            _ => {
                                println!("HTTP/1.1 from {}", remote_addr);
                                let _ = crate::protocol::http1::serve_connection(
                                    io, server, remote_addr
                                ).await;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("TLS error from {}: {}", remote_addr, e);
                    }
                }
            } else {
                let io = TokioIo::new(stream);
                let _ = crate::protocol::http1::serve_connection(
                    io, server, remote_addr
                ).await;
            }
        });
    }
}

    fn clone_refs(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            proxy_config: self.proxy_config.as_ref().map(Arc::clone),
            client: self.client.clone(),
            tls_acceptor: self.tls_acceptor.clone(),
            rate_limiter: self.rate_limiter.as_ref().map(Arc::clone),
            pf_blocker: self.pf_blocker.as_ref().map(Arc::clone),
            php_client: self.php_client.as_ref().map(Arc::clone),
            access_logger: self.access_logger.as_ref().map(Arc::clone),
            vhost_matcher: self.vhost_matcher.as_ref().map(Arc::clone),
        }
    }

    fn print_server_info(&self) {
        if let Some(ref proxy) = self.proxy_config {
            println!("📡 Proxy: {} backends", proxy.backends.len());
            for backend in &proxy.backends {
                println!("   - {} [{}]", backend.name, backend.url);
            }
        }

        if let Some(ref php) = self.config.php {
            println!("🐘 PHP: {}", php.fastcgi_addr);
        }

        if let Some(ref waf) = self.config.waf {
            if waf.enabled {
                println!("🛡️  WAF: {}", waf.rules_directory);
            }
        }

        if let Some(ref vhosts) = self.config.vhosts {
            println!("🌐 Virtual Hosts: {}", vhosts.len());
            for vhost in vhosts {
                if vhost.enabled {
                    println!("   - {}", vhost.server_name.join(", "));
                }
            }
        }

        println!("🔒 TLS: {}", if self.tls_acceptor.is_some() { "yes" } else { "no" });
    }

    fn is_php_request(&self, path: &str) -> bool {
        if let Some(ref php_config) = self.config.php {
            php_config.extensions.iter().any(|ext| path.ends_with(ext))
        } else {
            false
        }
    }

    fn is_php_request_for_vhost(&self, path: &str, vhost: &crate::vhost::matcher::VirtualHost) -> bool {
        if let Some(ref php_config) = vhost.php_config {
            php_config.extensions.iter().any(|ext| path.ends_with(ext))
        } else {
            false
        }
    }

    async fn handle_root(&self) -> Response<BoxBody<Bytes, Infallible>> {
        let body = Bytes::from(
            "<html><body><h1>Rust Web Server</h1>\
            <p>HTTP/2 + Proxy + PHP + WAF</p></body></html>"
        );
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Full::new(body).boxed())
            .unwrap();
        
        self.add_server_header(&mut response);
        response
    }

    async fn handle_health(&self) -> Response<BoxBody<Bytes, Infallible>> {
        let body = Bytes::from(r#"{"status":"ok"}"#);
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(body).boxed())
            .unwrap();
        
        self.add_server_header(&mut response);
        response
    }

    async fn handle_not_found(&self, ip: IpAddr) -> Response<BoxBody<Bytes, Infallible>> {
        // Record 404 hit
        if let Some(ref limiter) = self.rate_limiter {
            let exceeded = limiter.record_404(ip);
            
            if exceeded {
                // Block the IP if configured
                if let Some(ref blocker) = self.pf_blocker {
                    blocker.block(ip);
                }
            }
        }

        let body = Bytes::from("404 Not Found");
        let mut response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(body).boxed())
            .unwrap();
        
        self.add_server_header(&mut response);
        response
    }

    async fn handle_php(&self, req: Request<Incoming>, ip: IpAddr) -> Response<BoxBody<Bytes, Infallible>> {
        let path = req.uri().path();
        
        if let Some(ref php_client) = self.php_client {
            if let Some(ref php_config) = self.config.php {
                let script_filename = format!("{}{}", php_config.document_root, path);
                
                if !std::path::Path::new(&script_filename).exists() {
                    eprintln!("⚠️  PHP file not found: {}", script_filename);
                    return self.handle_not_found(ip).await;
                }

                match php_client.execute(req, &script_filename, ip).await {
                    Ok(php_response) => {
                        if !php_response.stderr.is_empty() {
                            eprintln!("PHP stderr: {}", php_response.stderr);
                        }

                        let mut response_builder = Response::builder()
                            .status(php_response.status);

                        for (key, value) in php_response.headers {
                            if let Ok(header_value) = hyper::header::HeaderValue::from_str(&value) {
                                response_builder = response_builder.header(&key, header_value);
                            }
                        }

                        let mut response = response_builder
                            .body(Full::new(Bytes::from(php_response.body)).boxed())
                            .unwrap();

                        self.add_server_header(&mut response);
                        return response;
                    }
                    Err(e) => {
                        eprintln!("❌ PHP execution error: {}", e);
                        let body = Bytes::from(format!("PHP Error: {}", e));
                        let mut response = Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::new(body).boxed())
                            .unwrap();
                        self.add_server_header(&mut response);
                        return response;
                    }
                }
            }
        }

        let body = Bytes::from("PHP not configured");
        let mut response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Full::new(body).boxed())
            .unwrap();
        self.add_server_header(&mut response);
        response
    }

    async fn handle_vhost_php(
        &self,
        req: Request<Incoming>,
        ip: IpAddr,
        vhost: &crate::vhost::matcher::VirtualHost,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let path = req.uri().path();
        
        if let Some(ref php_config) = vhost.php_config {
            // Create a PHP client for this vhost
            match crate::php::FastCgiClient::new(
                php_config.fastcgi_addr.clone(),
                php_config.document_root.clone(),
            ) {
                Ok(php_client) => {
                    let script_filename = format!("{}{}", php_config.document_root, path);
                    
                    if !std::path::Path::new(&script_filename).exists() {
                        eprintln!("⚠️  PHP file not found: {}", script_filename);
                        return self.handle_not_found(ip).await;
                    }

                    match php_client.execute(req, &script_filename, ip).await {
                        Ok(php_response) => {
                            if !php_response.stderr.is_empty() {
                                eprintln!("PHP stderr: {}", php_response.stderr);
                            }

                            let mut response_builder = Response::builder()
                                .status(php_response.status);

                            for (key, value) in php_response.headers {
                                if let Ok(header_value) = hyper::header::HeaderValue::from_str(&value) {
                                    response_builder = response_builder.header(&key, header_value);
                                }
                            }

                            let mut response = response_builder
                                .body(Full::new(Bytes::from(php_response.body)).boxed())
                                .unwrap();

                            self.add_server_header(&mut response);
                            return response;
                        }
                        Err(e) => {
                            eprintln!("❌ PHP execution error: {}", e);
                            let body = Bytes::from(format!("PHP Error: {}", e));
                            let mut response = Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(body).boxed())
                                .unwrap();
                            self.add_server_header(&mut response);
                            return response;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to create PHP client for vhost: {}", e);
                }
            }
        }

        self.handle_not_found(ip).await
    }

    fn add_server_header(&self, response: &mut Response<BoxBody<Bytes, Infallible>>) {
        if !self.config.server.hide_server_header {
            if let Ok(hv) = hyper::header::HeaderValue::from_str(
                &self.config.server.server_name
            ) {
                response.headers_mut().insert(hyper::header::SERVER, hv);
            }
        }
    }
}

impl RequestHandler for WebServer {
    async fn handle_request(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let ip = remote_addr.ip();
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let uri_path = path.clone();
        
        // Extract headers before moving req
        let host = req.headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let user_agent = req.headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let referer = req.headers()
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let start_time = Instant::now();

        // Check for virtual host match
        let vhost = self.vhost_matcher.as_ref()
            .and_then(|matcher| matcher.find_vhost(host.as_deref()));

        // Process request with vhost-aware routing
        let response = if let Some(vhost) = vhost {
            // VHost-specific handling
            match (&method, uri_path.as_str()) {
                (&Method::GET, "/health") => {
                    self.handle_health().await
                }
                // Check if PHP request for this vhost
                (_, p) if self.is_php_request_for_vhost(p, vhost) => {
                    self.handle_vhost_php(req, ip, vhost).await
                }
                // Check vhost proxy routes
                _ if vhost.proxy_backend.is_some() => {
                    let proxy_cfg = self.proxy_config.as_ref();
                    if let (Some(backend_name), Some(proxy_config)) = (&vhost.proxy_backend, proxy_cfg) {
                        if proxy_config.get_backend_by_name(backend_name).is_some() {
                            crate::proxy::handler::proxy_request(
                                req,
                                proxy_config,
                                &self.client,
                                &self.config.server.server_name,
                                self.config.server.hide_server_header,
                            ).await
                        } else {
                            eprintln!("⚠️  Backend '{}' not found for vhost", backend_name);
                            self.handle_not_found(ip).await
                        }
                    } else {
                        self.handle_not_found(ip).await
                    }
                }
                // Serve static files from vhost document root
                _ if vhost.document_root.is_some() => {
                    // TODO: Implement static file serving
                    // For now, return 404
                    self.handle_not_found(ip).await
                }
                _ => {
                    self.handle_not_found(ip).await
                }
            }
        } else {
            // No vhost match - use global config
            match (&method, uri_path.as_str()) {
                (&Method::GET, "/health") => {
                    self.handle_health().await
                }
                (_, p) if self.is_php_request(p) => {
                    self.handle_php(req, ip).await
                }
                _ if self.proxy_config.is_some() => {
                    let proxy_cfg = self.proxy_config.as_ref().unwrap();
                    if proxy_cfg.find_route(&uri_path).is_some() || !proxy_cfg.routes.is_empty() {
                        crate::proxy::handler::proxy_request(
                            req,
                            proxy_cfg,
                            &self.client,
                            &self.config.server.server_name,
                            self.config.server.hide_server_header,
                        ).await
                    } else {
                        self.handle_not_found(ip).await
                    }
                }
                _ => {
                    self.handle_not_found(ip).await
                }
            }
        };

        let response_time_ms = start_time.elapsed().as_millis() as u64;
        let status = response.status().as_u16();

        // Log the request
        if let Some(ref logger) = self.access_logger {
            logger.log(crate::logging::access_log::LogEntry {
                timestamp: chrono::Local::now(),
                ip,
                method: method.to_string(),
                path,
                status,
                user_agent,
                referer,
                response_time_ms,
            });
        } else {
            println!("{} {} {} {} {}ms", 
                ip, method, uri_path, status, response_time_ms);
        }

        Ok(response)
    }
}
