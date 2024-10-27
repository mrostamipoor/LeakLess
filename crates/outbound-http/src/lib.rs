pub mod allowed_http_hosts;
mod host_component;

use std::str::FromStr;

use anyhow::Result;
use http::HeaderMap;
use reqwest::{Client, Url};
use spin_app::MetadataKey;
use spin_core::{
    async_trait, http as outbound_http,
    http_types::{HeadersParam, HttpError, Method, RequestResult, Response},
};

use allowed_http_hosts::AllowedHttpHosts;
pub use host_component::OutboundHttpComponent;
use hyper::header::{HeaderName, HeaderValue};

pub const ALLOWED_HTTP_HOSTS_KEY: MetadataKey<Vec<String>> = MetadataKey::new("allowed_http_hosts");

/// A very simple implementation for outbound HTTP requests.
#[derive(Default, Clone)]
pub struct OutboundHttp {
    /// List of hosts guest modules are allowed to make requests to.
    pub allowed_hosts: AllowedHttpHosts,
    pub component_id: String,
    client: Option<Client>,
}
use reqwest::Proxy;
impl OutboundHttp {
    /// Check if guest module is allowed to send request to URL, based on the list of
    /// allowed hosts defined by the runtime. If the list of allowed hosts contains
    /// `insecure:allow-all`, then all hosts are allowed.
    /// If `None` is passed, the guest module is not allowed to send the request.
    fn is_allowed(&self, url: &str) -> Result<bool, HttpError> {
        let url = Url::parse(url).map_err(|_| HttpError::InvalidUrl)?;
        Ok(self.allowed_hosts.allow(&url))
    }
    fn create_client_with_proxy(&self) -> Result<Client, HttpError> {
         //Retrieve the proxy URL from an environment variable or configuration file
        let proxy_url ="http://0.0.0.0:3002";
        //let proxy_url ="http://130.245.42.182:1234";
        // Parse the proxy URL
        let proxy = Proxy::all(&*proxy_url).unwrap();
        // Configure the `Client` with the proxy
        let client = Client::builder().proxy(proxy).danger_accept_invalid_certs(true).build().unwrap();
        Ok(client)
    }
}

#[async_trait]
impl outbound_http::Host for OutboundHttp {
    async fn send_request(&mut self, req: RequestResult) -> Result<Result<Response, HttpError>> {
        Ok(async {
            tracing::log::trace!("Attempting to send outbound HTTP request to {}", req.uri);
            if !self.is_allowed(&req.uri).map_err(|_| HttpError::RuntimeError)? {
                tracing::log::info!("Destination not allowed: {}", req.uri);
                return Err(HttpError::DestinationNotAllowed);
            }
            let tmp = "LeakLess-Header";
            let custom_header_name = HeaderName::from_str(&tmp).unwrap();
            let custom_header_value = HeaderValue::from_str(&self.component_id).unwrap();
            let method = method_from(req.method);
            let url = Url::parse(&req.uri).map_err(|_| HttpError::InvalidUrl)?;
            let mut headers = request_headers(
                &req.headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| HttpError::RuntimeError)?;
            let body = req.body.unwrap_or_default().to_vec();
            headers.insert(custom_header_name.clone(), custom_header_value.clone());
            if !req.params.is_empty() {
                tracing::log::warn!("HTTP params field is deprecated");
            }
            // Check if the headers or body contain "LeakLess_"
            let headers_contain_leakless = headers.iter().any(|(_name, value)| {
                let header_value = value.to_str().unwrap_or("").to_owned();
                header_value.contains("LEAKLESS_")
            });
            let body_contain_leakless = String::from_utf8_lossy(&body).contains("LEAKLESS_");

            let file_exists = std::path::Path::new("services").exists();
            let client = if headers_contain_leakless || body_contain_leakless ||file_exists {
                self.create_client_with_proxy().unwrap()
            } else {
                let client = self.client.get_or_insert_with(Default::default);
                client.clone()
            };
            let resp = client
                .request(method, url)
                .headers(headers)
                .body(body)
                .send()
                .await
                .map_err(log_reqwest_error)?;
            tracing::log::trace!("Returning response from outbound request to {}", req.uri);
            response_from_reqwest(resp).await
        }
        .await)
    }
}

fn log_reqwest_error(err: reqwest::Error) -> HttpError {
    let error_desc = if err.is_timeout() {
        "timeout error"
    } else if err.is_connect() {
        "connection error"
    } else if err.is_body() || err.is_decode() {
        "message body error"
    } else if err.is_request() {
        "request error"
    } else {
        "error"
    };
    tracing::warn!(
        "Outbound HTTP {}: URL {}, error detail {:?}",
        error_desc,
        err.url()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned()),
        err
    );
    HttpError::RuntimeError
}

fn method_from(m: Method) -> http::Method {
    match m {
        Method::Get => http::Method::GET,
        Method::Post => http::Method::POST,
        Method::Put => http::Method::PUT,
        Method::Delete => http::Method::DELETE,
        Method::Patch => http::Method::PATCH,
        Method::Head => http::Method::HEAD,
        Method::Options => http::Method::OPTIONS,
    }
}

async fn response_from_reqwest(res: reqwest::Response) -> Result<Response, HttpError> {
    let status = res.status().as_u16();
    let headers = response_headers(res.headers()).map_err(|_| HttpError::RuntimeError)?;

    let body = Some(
        res.bytes()
            .await
            .map_err(|_| HttpError::RuntimeError)?
            .to_vec(),
    );

    Ok(Response {
        status,
        headers,
        body,
    })
}

fn request_headers(h: HeadersParam) -> anyhow::Result<HeaderMap> {
    let mut res = HeaderMap::new();
    for (k, v) in h {
        res.insert(
            http::header::HeaderName::from_str(k)?,
            http::header::HeaderValue::from_str(v)?,
        );
    }
    Ok(res)
}

fn response_headers(h: &HeaderMap) -> anyhow::Result<Option<Vec<(String, String)>>> {
    let mut res: Vec<(String, String)> = vec![];

    for (k, v) in h {
        res.push((
            k.to_string(),
            std::str::from_utf8(v.as_bytes())?.to_string(),
        ));
    }

    Ok(Some(res))
}