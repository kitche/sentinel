use hyper::{Request, Response, body::Incoming, StatusCode, Uri};
use hyper::header::{HeaderValue, CONNECTION, UPGRADE, PROXY_AUTHENTICATE, 
                     PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use http_body_util::{Full, BodyExt, combinators::BoxBody};
use hyper::body::Bytes;
use std::convert::Infallible;
use crate::proxy::ProxyConfig;

pub async fn proxy_request(
    mut req: Request<Incoming>,
    proxy_config: &ProxyConfig,
    client: &Client<HttpConnector, Incoming>,
    server_name: &str,
    hide_server_header: bool,
) -> Response<BoxBody<Bytes, Infallible>> {
    let path = req.uri().path();
    
    let backend = if let Some(route) = proxy_config.find_route(path) {
        proxy_config.get_backend_by_name(&route.backend)
    } else {
        proxy_config.get_next_backend()
    };

    let backend = match backend {
        Some(b) => b,
        None => {
            let body = Bytes::from("No backend servers available");
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(body).boxed())
                .unwrap();
        }
    };

    let backend_uri = match build_backend_uri(&backend.url, req.uri()) {
        Ok(uri) => uri,
        Err(e) => {
            eprintln!("Failed to build backend URI: {}", e);
            let body = Bytes::from("Internal Server Error");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(body).boxed())
                .unwrap();
        }
    };

    println!("Proxying to: {} -> {}", backend.name, backend_uri);

    *req.uri_mut() = backend_uri;
    sanitize_request_headers(req.headers_mut());

    match client.request(req).await {
        Ok(response) => {
            let (mut parts, body) = response.into_parts();
            
            sanitize_response_headers(&mut parts.headers);
            parts.headers.insert(
                "X-Proxied-By",
                HeaderValue::from_static("KitcheServer/1.0")
            );
            
            if !hide_server_header {
                if let Ok(hv) = HeaderValue::from_str(server_name) {
                    parts.headers.insert(hyper::header::SERVER, hv);
                }
            }
            
            // Map the error type from hyper::Error to Infallible
            let boxed_body = body.map_err(|_| unreachable!()).boxed();
            Response::from_parts(parts, boxed_body)
        }
        Err(e) => {
            eprintln!("Proxy error: {}", e);
            let body = Bytes::from(format!("Bad Gateway: {}", e));
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(body).boxed())
                .unwrap()
        }
    }
}

fn build_backend_uri(backend_url: &str, original_uri: &Uri) 
    -> Result<Uri, Box<dyn std::error::Error>> {
    let pq = original_uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let uri = format!("{}{}", backend_url, pq);
    Ok(uri.parse()?)
}

fn sanitize_request_headers(headers: &mut hyper::HeaderMap) {
    headers.remove(CONNECTION);
    headers.remove(UPGRADE);
    headers.remove(PROXY_AUTHENTICATE);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove(TRANSFER_ENCODING);
    headers.remove("Keep-Alive");

    if !headers.contains_key("X-Forwarded-Proto") {
        headers.insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
    }
}

fn sanitize_response_headers(headers: &mut hyper::HeaderMap) {
    headers.remove(CONNECTION);
    headers.remove(UPGRADE);
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove("Keep-Alive");
}
