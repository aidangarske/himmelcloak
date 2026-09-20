/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use curl::easy::{Easy, List};
use url::Url;
use zeroize::Zeroize;

use crate::error::{Error, Result};

const MAX_RESPONSE: usize = 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum Method {
    Get,
    Post,
}

pub(crate) struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<String>,
    pub body: Vec<u8>,
    pub cookies: Vec<String>,
}

impl Request {
    pub fn get(url: Url) -> Self {
        Self {
            method: Method::Get,
            url,
            headers: Vec::new(),
            body: Vec::new(),
            cookies: Vec::new(),
        }
    }

    pub fn form(url: Url, fields: &[(&str, &str)]) -> Self {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish()
            .into_bytes();
        Self {
            method: Method::Post,
            url,
            headers: vec!["Content-Type: application/x-www-form-urlencoded".to_owned()],
            body,
            cookies: Vec::new(),
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.body.zeroize();
        self.headers.zeroize();
        self.cookies.zeroize();
    }
}

pub(crate) struct Response {
    pub status: u32,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub cookies: Vec<String>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        self.body.zeroize();
        for (name, value) in &mut self.headers {
            name.zeroize();
            value.zeroize();
        }
        self.cookies.zeroize();
    }
}

pub(crate) trait HttpTransport: Send + Sync {
    fn send(&self, request: Request)
        -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>>;
}

#[derive(Clone)]
pub(crate) struct CurlTransport {
    ca_bundle: Option<PathBuf>,
    timeout: Duration,
}

impl CurlTransport {
    pub fn new(ca_bundle: Option<PathBuf>, timeout: Duration) -> Result<Self> {
        let backend = curl::Version::get()
            .ssl_version()
            .unwrap_or_default()
            .to_owned();
        if !backend.to_ascii_lowercase().contains("wolfssl") {
            return Err(Error::TlsBackend);
        }
        Ok(Self { ca_bundle, timeout })
    }
}

impl HttpTransport for CurlTransport {
    fn send(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
        let ca_bundle = self.ca_bundle.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let runtime = tokio::runtime::Handle::try_current()
                .map_err(|_| Error::Transport("Tokio runtime required".to_owned()))?;
            runtime
                .spawn_blocking(move || send_blocking(request, ca_bundle, timeout))
                .await
                .map_err(|_| Error::Transport("HTTP worker failed".to_owned()))?
        })
    }
}

fn send_blocking(
    request: Request,
    ca_bundle: Option<PathBuf>,
    timeout: Duration,
) -> Result<Response> {
    let mut easy = Easy::new();
    easy.url(request.url.as_str()).map_err(curl_error)?;
    // Loopback HTTP is allowed for local tests; never send its credentials
    // through a proxy selected from the process environment.
    if request.url.scheme() == "http" {
        easy.proxy("").map_err(curl_error)?;
    }
    easy.timeout(timeout).map_err(curl_error)?;
    easy.connect_timeout(timeout).map_err(curl_error)?;
    easy.follow_location(false).map_err(curl_error)?;
    easy.ssl_verify_peer(true).map_err(curl_error)?;
    easy.ssl_verify_host(true).map_err(curl_error)?;
    easy.useragent(concat!("himmelcloak/", env!("CARGO_PKG_VERSION")))
        .map_err(curl_error)?;
    if let Some(path) = ca_bundle {
        easy.cainfo(path).map_err(curl_error)?;
    }
    easy.cookie_file("").map_err(curl_error)?;
    for cookie in &request.cookies {
        easy.cookie_list(cookie).map_err(curl_error)?;
    }
    if !request.headers.is_empty() {
        let mut headers = List::new();
        for header in &request.headers {
            headers.append(header).map_err(curl_error)?;
        }
        easy.http_headers(headers).map_err(curl_error)?;
    }
    if matches!(request.method, Method::Post) {
        easy.post(true).map_err(curl_error)?;
        easy.post_field_size(request.body.len() as u64)
            .map_err(curl_error)?;
    }

    let mut response = Response {
        status: 0,
        headers: Vec::new(),
        body: Vec::new(),
        cookies: Vec::new(),
    };
    let mut header_bytes = 0usize;
    let mut sent_bytes = 0usize;
    let oversized = std::cell::Cell::new(false);
    let transfer_result = {
        let mut transfer = easy.transfer();
        transfer
            .read_function(|buffer| {
                let remaining = &request.body[sent_bytes..];
                let count = remaining.len().min(buffer.len());
                buffer[..count].copy_from_slice(&remaining[..count]);
                sent_bytes += count;
                Ok(count)
            })
            .map_err(curl_error)?;
        transfer
            .write_function(|bytes| {
                if response.body.len().saturating_add(bytes.len()) > MAX_RESPONSE {
                    oversized.set(true);
                    return Ok(0);
                }
                response.body.extend_from_slice(bytes);
                Ok(bytes.len())
            })
            .map_err(curl_error)?;
        transfer
            .header_function(|line| {
                header_bytes = header_bytes.saturating_add(line.len());
                if header_bytes > MAX_HEADERS {
                    oversized.set(true);
                    return false;
                }
                if let Ok(line) = std::str::from_utf8(line) {
                    if let Some((name, value)) = line.split_once(':') {
                        response
                            .headers
                            .push((name.trim().to_owned(), value.trim().to_owned()));
                    }
                }
                true
            })
            .map_err(curl_error)?;
        transfer.perform()
    };
    if oversized.get() {
        return Err(Error::Protocol("HTTP response too large"));
    }
    transfer_result.map_err(curl_error)?;
    response.status = easy.response_code().map_err(curl_error)?;
    for cookie in easy.cookies().map_err(curl_error)?.iter() {
        let cookie =
            std::str::from_utf8(cookie).map_err(|_| Error::Protocol("invalid cookie encoding"))?;
        response.cookies.push(cookie.to_owned());
    }
    Ok(response)
}

fn curl_error(error: curl::Error) -> Error {
    Error::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;

    use super::{send_blocking, CurlTransport, HttpTransport, Request, MAX_HEADERS, MAX_RESPONSE};
    use crate::error::Error;
    use url::Url;

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    #[test]
    fn missing_tokio_runtime_returns_an_error() {
        let transport = CurlTransport {
            ca_bundle: None,
            timeout: std::time::Duration::from_secs(2),
        };
        let request = Request::get(Url::parse("http://127.0.0.1:9/").unwrap());
        let mut future = transport.send(request);
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::Transport(message))) if message == "Tokio runtime required"
        ));
    }

    fn serve(header_size: usize, body_size: usize) -> (Url, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let thread = thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 || request.len() > 8192 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
            }
            let prefix = format!("HTTP/1.1 200 OK\r\nContent-Length: {body_size}\r\nX-Pad: ");
            let suffix = "\r\n\r\n";
            let pad = "x".repeat(header_size - prefix.len() - suffix.len());
            let headers = format!("{prefix}{pad}{suffix}");
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(&vec![b'x'; body_size]);
        });
        (url, thread)
    }

    #[test]
    fn response_limits_accept_boundaries_and_reject_oversize() {
        for (header_size, body_size, allowed) in [
            (128, MAX_RESPONSE, true),
            (128, MAX_RESPONSE + 1, false),
            (MAX_HEADERS, 0, true),
            (MAX_HEADERS + 1, 0, false),
        ] {
            let (url, server) = serve(header_size, body_size);
            let response =
                send_blocking(Request::get(url), None, std::time::Duration::from_secs(5));
            server.join().unwrap();
            if allowed {
                assert_eq!(response.unwrap().body.len(), body_size);
            } else {
                assert!(matches!(
                    response,
                    Err(Error::Protocol("HTTP response too large"))
                ));
            }
        }
    }

    #[test]
    fn loopback_http_does_not_use_environment_proxy() {
        let keys = ["http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"];
        let previous: Vec<_> = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();
        std::env::set_var("http_proxy", "http://127.0.0.1:9");
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:9");
        std::env::remove_var("no_proxy");
        std::env::remove_var("NO_PROXY");

        let (url, server) = serve(128, 0);
        let response = send_blocking(Request::get(url), None, std::time::Duration::from_secs(5));
        for (key, value) in previous {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
        server.join().unwrap();
        assert_eq!(response.unwrap().status, 200);
    }
}
