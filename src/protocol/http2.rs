use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use crate::server::RequestHandler;

pub async fn serve_connection<S>(
    io: TokioIo<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>,
    server: Arc<S>,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: RequestHandler + Send + Sync + 'static,
{
    http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service_fn(move |req| {
            let server = Arc::clone(&server);
            async move { server.handle_request(req, remote_addr).await }
        }))
        .await?;
    Ok(())
}
