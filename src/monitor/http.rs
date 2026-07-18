//! Shared HTTP helpers for bounded, low-noise monitoring probes.

use reqwest::Response;

/// Largest response prefix retained by lightweight HTTP probes.
///
/// Enumeration only needs enough content to identify error pages and links, and
/// the source-map POC only needs marker text. Keeping this bounded avoids
/// buffering arbitrarily large responses in memory.
pub const MAX_RESPONSE_BODY_BYTES: usize = 256 * 1024;

/// Reads at most `max_bytes` from an HTTP response body.
///
/// The returned text is decoded lossily so probing remains resilient to pages
/// with an invalid or unspecified character encoding.
pub async fn response_text_prefix(
    mut response: Response,
    max_bytes: usize,
) -> Result<String, reqwest::Error> {
    if max_bytes == 0 {
        return Ok(String::new());
    }

    let mut body = Vec::with_capacity(max_bytes);
    while let Some(chunk) = response.chunk().await? {
        let remaining = max_bytes.saturating_sub(body.len());
        if remaining == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if body.len() == max_bytes {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    async fn serve_once(body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });
        format!("http://{address}/")
    }

    #[tokio::test]
    async fn reads_only_the_requested_response_prefix() {
        let url = serve_once(b"abcdef").await;
        let response = reqwest::Client::new().get(url).send().await.unwrap();

        assert_eq!(response_text_prefix(response, 4).await.unwrap(), "abcd");
    }

    #[tokio::test]
    async fn accepts_zero_length_prefix_without_reading_the_body() {
        let url = serve_once(b"abcdef").await;
        let response = reqwest::Client::new().get(url).send().await.unwrap();

        assert_eq!(response_text_prefix(response, 0).await.unwrap(), "");
    }
}
