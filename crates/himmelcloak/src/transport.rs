/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
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
            tokio::task::spawn_blocking(move || send_blocking(request, ca_bundle, timeout))
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
    easy.timeout(timeout).map_err(curl_error)?;
    easy.connect_timeout(timeout).map_err(curl_error)?;
    easy.follow_location(false).map_err(curl_error)?;
    easy.ssl_verify_peer(true).map_err(curl_error)?;
    easy.ssl_verify_host(true).map_err(curl_error)?;
    easy.useragent("himmelcloak/0.1").map_err(curl_error)?;
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
        easy.post_fields_copy(&request.body).map_err(curl_error)?;
    }

    let mut response = Response {
        status: 0,
        headers: Vec::new(),
        body: Vec::new(),
        cookies: Vec::new(),
    };
    let mut header_bytes = 0usize;
    let oversized = std::cell::Cell::new(false);
    let transfer_result = {
        let mut transfer = easy.transfer();
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
