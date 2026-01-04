use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use hyper::{Request, body::Incoming};
use http_body_util::BodyExt;

const FCGI_VERSION_1: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;

const FCGI_RESPONDER: u16 = 1;

#[derive(Debug)]
pub struct FastCgiResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub stderr: String,
}

pub struct FastCgiClient {
    addr: SocketAddr,
    document_root: String,
}

impl FastCgiClient {
    pub fn new(addr: String, document_root: String) -> Result<Self, String> {
        let socket_addr: SocketAddr = addr.parse()
            .map_err(|e| format!("Invalid address: {}", e))?;
        Ok(Self {
            addr: socket_addr,
            document_root,
        })
    }

    pub async fn execute(
        &self,
        req: Request<Incoming>,
        script_filename: &str,
        remote_addr: std::net::IpAddr,
    ) -> Result<FastCgiResponse, String> {
        let mut stream = TcpStream::connect(self.addr).await
            .map_err(|e| format!("Connection error: {}", e))?;

        let params = self.build_params(&req, script_filename, remote_addr)?;
        let body = self.read_request_body(req).await?;

        let request_id = 1u16;
        
        self.send_begin_request(&mut stream, request_id).await?;
        self.send_params(&mut stream, request_id, &params).await?;
        self.send_stdin(&mut stream, request_id, &body).await?;
        
        let response = self.read_response(&mut stream, request_id).await?;

        Ok(response)
    }

    fn build_params(
        &self,
        req: &Request<Incoming>,
        script_filename: &str,
        remote_addr: std::net::IpAddr,
    ) -> Result<HashMap<String, String>, String> {
        let mut params = HashMap::new();

        params.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
        params.insert("SERVER_SOFTWARE".to_string(), "RustWebServer/1.0".to_string());
        params.insert("SERVER_PROTOCOL".to_string(), format!("{:?}", req.version()));
        
        params.insert("REQUEST_METHOD".to_string(), req.method().to_string());
        params.insert("REQUEST_URI".to_string(), req.uri().to_string());
        params.insert("QUERY_STRING".to_string(), 
            req.uri().query().unwrap_or("").to_string());
        
        params.insert("SCRIPT_FILENAME".to_string(), script_filename.to_string());
        params.insert("SCRIPT_NAME".to_string(), req.uri().path().to_string());
        params.insert("DOCUMENT_ROOT".to_string(), self.document_root.clone());
        
        params.insert("REMOTE_ADDR".to_string(), remote_addr.to_string());
        params.insert("REMOTE_PORT".to_string(), "0".to_string());
        
        params.insert("SERVER_NAME".to_string(), 
            req.headers().get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost")
                .to_string());
        params.insert("SERVER_PORT".to_string(), "80".to_string());
        
        if let Some(content_type) = req.headers().get("content-type") {
            params.insert("CONTENT_TYPE".to_string(), 
                content_type.to_str().unwrap_or("").to_string());
        }
        
        if let Some(content_length) = req.headers().get("content-length") {
            params.insert("CONTENT_LENGTH".to_string(), 
                content_length.to_str().unwrap_or("0").to_string());
        }

        for (name, value) in req.headers() {
            let header_name = format!("HTTP_{}", 
                name.as_str().to_uppercase().replace("-", "_"));
            if let Ok(value_str) = value.to_str() {
                params.insert(header_name, value_str.to_string());
            }
        }

        Ok(params)
    }

    async fn read_request_body(&self, req: Request<Incoming>) -> Result<Vec<u8>, String> {
        let body = req.into_body();
        let collected = body.collect().await
            .map_err(|e| format!("Failed to read body: {}", e))?;
        Ok(collected.to_bytes().to_vec())
    }

    async fn send_begin_request(
        &self,
        stream: &mut TcpStream,
        request_id: u16,
    ) -> Result<(), String> {
        let mut record = vec![0u8; 16];
        
        record[0] = FCGI_VERSION_1;
        record[1] = FCGI_BEGIN_REQUEST;
        record[2..4].copy_from_slice(&request_id.to_be_bytes());
        record[4..6].copy_from_slice(&8u16.to_be_bytes());
        
        record[8..10].copy_from_slice(&FCGI_RESPONDER.to_be_bytes());
        record[10] = 0;
        
        stream.write_all(&record).await
            .map_err(|e| format!("Write error: {}", e))?;
        Ok(())
    }

    async fn send_params(
        &self,
        stream: &mut TcpStream,
        request_id: u16,
        params: &HashMap<String, String>,
    ) -> Result<(), String> {
        let mut content = Vec::new();

        for (key, value) in params {
            self.encode_name_value(&mut content, key.as_bytes(), value.as_bytes());
        }

        for chunk in content.chunks(65535) {
            self.send_record(stream, FCGI_PARAMS, request_id, chunk).await?;
        }

        self.send_record(stream, FCGI_PARAMS, request_id, &[]).await?;

        Ok(())
    }

    fn encode_name_value(&self, buf: &mut Vec<u8>, name: &[u8], value: &[u8]) {
        self.encode_length(buf, name.len());
        self.encode_length(buf, value.len());
        
        buf.extend_from_slice(name);
        buf.extend_from_slice(value);
    }

    fn encode_length(&self, buf: &mut Vec<u8>, len: usize) {
        if len < 128 {
            buf.push(len as u8);
        } else {
            buf.push((len >> 24) as u8 | 0x80);
            buf.push((len >> 16) as u8);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }

    async fn send_stdin(
        &self,
        stream: &mut TcpStream,
        request_id: u16,
        body: &[u8],
    ) -> Result<(), String> {
        if !body.is_empty() {
            for chunk in body.chunks(65535) {
                self.send_record(stream, FCGI_STDIN, request_id, chunk).await?;
            }
        }

        self.send_record(stream, FCGI_STDIN, request_id, &[]).await?;

        Ok(())
    }

    async fn send_record(
        &self,
        stream: &mut TcpStream,
        record_type: u8,
        request_id: u16,
        content: &[u8],
    ) -> Result<(), String> {
        let content_len = content.len() as u16;
        let padding_len = (8 - (content_len % 8)) % 8;

        let mut header = [0u8; 8];
        header[0] = FCGI_VERSION_1;
        header[1] = record_type;
        header[2..4].copy_from_slice(&request_id.to_be_bytes());
        header[4..6].copy_from_slice(&content_len.to_be_bytes());
        header[6] = padding_len as u8;

        stream.write_all(&header).await
            .map_err(|e| format!("Write error: {}", e))?;
        stream.write_all(content).await
            .map_err(|e| format!("Write error: {}", e))?;
        
        if padding_len > 0 {
            stream.write_all(&vec![0u8; padding_len as usize]).await
                .map_err(|e| format!("Write error: {}", e))?;
        }

        Ok(())
    }

    async fn read_response(
        &self,
        stream: &mut TcpStream,
        request_id: u16,
    ) -> Result<FastCgiResponse, String> {
        let mut stdout_data = Vec::new();
        let mut stderr_data = Vec::new();

        loop {
            let mut header = [0u8; 8];
            stream.read_exact(&mut header).await
                .map_err(|e| format!("Read error: {}", e))?;

            let version = header[0];
            let record_type = header[1];
            let rec_request_id = u16::from_be_bytes([header[2], header[3]]);
            let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
            let padding_len = header[6] as usize;

            if version != FCGI_VERSION_1 || rec_request_id != request_id {
                continue;
            }

            let mut content = vec![0u8; content_len];
            if content_len > 0 {
                stream.read_exact(&mut content).await
                    .map_err(|e| format!("Read error: {}", e))?;
            }

            if padding_len > 0 {
                let mut padding = vec![0u8; padding_len];
                stream.read_exact(&mut padding).await
                    .map_err(|e| format!("Read error: {}", e))?;
            }

            match record_type {
                FCGI_STDOUT => {
                    stdout_data.extend_from_slice(&content);
                }
                FCGI_STDERR => {
                    stderr_data.extend_from_slice(&content);
                }
                FCGI_END_REQUEST => {
                    break;
                }
                _ => {}
            }
        }

        self.parse_http_response(stdout_data, stderr_data)
    }

    fn parse_http_response(
        &self,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<FastCgiResponse, String> {
        let response_str = String::from_utf8_lossy(&stdout);
        let stderr_str = String::from_utf8_lossy(&stderr).to_string();

        let parts: Vec<&str> = response_str.splitn(2, "\r\n\r\n").collect();
        if parts.len() < 2 {
            return Err("Invalid FastCGI response".to_string());
        }

        let headers_str = parts[0];
        let body = parts[1].as_bytes().to_vec();

        let mut headers = HashMap::new();
        let mut status = 200u16;

        for line in headers_str.lines() {
            if let Some((key, value)) = line.split_once(": ") {
                if key.eq_ignore_ascii_case("status") {
                    if let Some(code_str) = value.split_whitespace().next() {
                        status = code_str.parse().unwrap_or(200);
                    }
                } else {
                    headers.insert(key.to_string(), value.to_string());
                }
            }
        }

        Ok(FastCgiResponse {
            status,
            headers,
            body,
            stderr: stderr_str,
        })
    }
}
