use anyhow::Result;
use futures_util::{Stream, StreamExt};
use hyper::body::{Bytes, HttpBody};
use hyper::client::conn::Builder;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io::Write;

async fn self_bits() -> Result<impl Stream<Item = std::io::Result<Bytes>>> {
    let mut ret = futures_util::stream::empty().boxed();
    for _ in 0..6 {
        let f = tokio::fs::File::open("/proc/self/exe").await?;
        let f = tokio_util::io::ReaderStream::new(f);
        ret = ret.chain(f).boxed();
    }
    Ok(ret)
}

async fn serve(_req: Request<Body>) -> Result<Response<Body>> {
    Ok(Response::new(Body::wrap_stream(self_bits().await?)))
}

#[tokio::main]
async fn main() -> Result<()> {
    let self_digest = {
        let mut digester = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;
        let mut bits = self_bits().await?;
        while let Some(buf) = bits.next().await {
            let buf = buf?;
            digester.write_all(&buf)?;
        }
        digester.finish()?
    };
    let self_digest: &[u8] = &self_digest;

    let (mysock, childsock) = tokio::net::UnixStream::pair()?;
    let _server = tokio::task::spawn(async move {
        if let Err(http_err) = Http::new()
            .serve_connection(childsock, service_fn(serve))
            .await
        {
            eprintln!("Error while serving HTTP connection: {}", http_err);
        }
    });
    // Connect via HTTP to the child
    let (mut request_sender, connection) = Builder::new().handshake::<_, Body>(mysock).await?;
    // Background driver that manages things like timeouts.
    let _driver = tokio::spawn(connection);

    for _ in 0..2 {
        let req = Request::builder()
            .header("Host", "localhost")
            .method("GET")
            .uri("/")
            .body(Body::from(""))?;
        let mut resp = request_sender.send_request(req).await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("request error: {}", resp.status()));
        }
        let mut fetched_digest =
            openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;
        while let Some(chunk) = resp.body_mut().data().await {
            let chunk = chunk?;
            fetched_digest.write_all(&chunk)?;
        }
        let fetched_digest = fetched_digest.finish()?;
        let fetched_digest: &[u8] = &fetched_digest;
        assert_eq!(self_digest, fetched_digest);
    }

    Ok(())
}
