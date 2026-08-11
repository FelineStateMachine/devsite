//! Stand-in for a real local developer service.
//!
//! Serves one self-contained HTML file on a loopback port, for any path. This is what
//! `127.0.0.1:4101` (Hermes) and `127.0.0.1:4102` (Agent) are during the vertical slice.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let port: u16 = args
        .next()
        .context("usage: devsite-fixture <port> <file.html>")?
        .parse()
        .context("port must be a number")?;
    let path = PathBuf::from(
        args.next()
            .context("usage: devsite-fixture <port> <file.html>")?,
    );

    let body = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    println!(
        "devsite-fixture: serving {} on http://127.0.0.1:{port}",
        path.display()
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let body = body.clone();
        tokio::spawn(async move {
            if let Err(err) = serve(stream, &body).await {
                eprintln!("devsite-fixture: connection error: {err:#}");
            }
        });
    }
}

async fn serve(mut stream: TcpStream, body: &[u8]) -> Result<()> {
    // Read just enough to consume the request line and headers; we serve the same file
    // regardless of path, so the request contents don't matter.
    let mut buf = [0u8; 4096];
    let _ = stream.read(&mut buf).await?;

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
