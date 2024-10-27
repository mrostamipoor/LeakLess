use anyhow::Result;
use http::{Method, StatusCode};
use spin_sdk::{
    config,
    http::{Request, Response},
    http_component,
    key_value::{Error, Store},
};
//This main structure code comes from this cloudflare worker example:
//https://github.com/openchargemap/ocm-system/tree/de410868604ccd2f55743773f6934f9c3ab9123c/API/OCM.Net/OCM.API.Worker/cloudflare/api-router
//However the goal was only implementing the main part for handling sesntive data
use http::HeaderMap;


fn handle_options_request(_req: &Request) -> Result<Response> {
    Ok(http::Response::builder().status(StatusCode::OK).body(None)?)
}
const BANNED_UA: &[&str] = &[
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
    "Mozilla/5.0 (compatible; SemrushBot/6~bl; +http://www.semrush.com/bot.html)"
];
fn is_banned_request(headers: &HeaderMap) -> bool {
    // Check for banned User Agents or IPs
    // ...
    if let Some(user_agent) = headers.get("User-Agent") {
        if let Ok(ua_string) = user_agent.to_str() {
            return BANNED_UA.iter().any(|&banned| ua_string.contains(banned));
        }
    }

    false
}

fn is_api_key_valid(api_key: &str) -> bool {
    let preshared_auth_header_value= config::get("notion_key").expect("Failed to acquire dotenv from spin.toml");
    api_key == preshared_auth_header_value
}

fn handle_post_request(req: &Request, store: &Store) -> Result<Response> {
    // POST request handling
    let new_uri_str = "http://0.0.0.0:5000/check-header";
    let new_uri = new_uri_str.parse::<http::Uri>().map_err(|e| http::Error::from(e))?;
    let api_key = req.headers().get("notion-key").and_then(|v| v.to_str().ok()).map(|s| s.as_bytes()).unwrap_or(&[]);
    //req.headers().remove("api-key");
    let path=req.uri().path();
    store.set(path, api_key)?;
    //println!("Logged user API path: {:?}", path);

    let mut request_builder = http::Request::builder()
        .method(req.method())
        .uri(new_uri);
    
    for (key, value) in req.headers().iter() {
        if key != "Notion-key"{
            request_builder = request_builder.header(key, value);
        }
    }
    
    let res = spin_sdk::outbound_http::send_request(
        request_builder
            .body(req.body().as_ref().map(|b| b.clone()))?,
    )?;
    //println!("Logged user API path: {:?}", path);
    let cloned_body = res.body().clone();
    Ok(http::Response::builder().status(StatusCode::OK).body(cloned_body)?)
}
#[http_component]
fn handle_request(req: Request) -> Result<Response> {
    // Open the default key-value store
    let store = Store::open_default()?;
    //let secret_value = req.headers().get("PRESHARED-KEY").unwrap();
    if is_banned_request(req.headers()) {
        return Ok(http::Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Some("Access denied".into()))?);
    }
    let path = req.uri().path();
    if path == "/robots.txt" {

        return Ok(http::Response::builder()
        .status(403)
        .header("CONTENT_TYPE", "text/plain")
        .body(Some("user-agent: * \r\ndisallow: /".into()))?);
    }
    

    // Handling /.well-known/ path
    if path.contains("/.well-known/") {
        let new_uri_str = format!("http://api-01.openchargemap.io{}", path);
        let new_uri = new_uri_str.parse::< http::Uri>().map_err(|e| http::Error::from(e))?;
        let res = spin_sdk::outbound_http::send_request(
            http::Request::builder()
                .method(req.method())
                .uri(new_uri)
                .body(None)?,
        )?;
        return Ok(res);
    }

    if let Some(user_agent) = req.headers().get("User-Agent") {
        if user_agent.to_str().map_or(false, |ua| ua.contains("FME/2020")) {
            return Ok(http::Response::builder()
            .status(403)
            .header("CONTENT_TYPE", "text/plain")
            .body(Some("Blocked for API Abuse. Callers spamming API with repeated duplicate calls may be auto banned.".into()))?);
        }

    }


    let api_key = req.headers().get("Notion-key").and_then(|v| v.to_str().ok());
    if api_key.is_none() || !is_api_key_valid(api_key.unwrap()) {
        return Ok(http::Response::builder()
        .status(403)
        .body(Some("You are not authroized to read this file".into()))?);
    }

    let (status, body) = match req.method() {
        &Method::POST => {
            //println!("heere");
            return handle_post_request(&req, &store)}
        &Method::GET => {
            // Get the value associated with the request URI, or return a 404 if it's not present
            match store.get(req.uri().path()) {
                Ok(value) => (StatusCode::OK, Some(value.into())),
                Err(Error::NoSuchKey) => (StatusCode::NOT_FOUND, None),
                Err(error) => return Err(error.into()),
            }
        }
        &Method::DELETE => {
            // Delete the value associated with the request URI, if present
            store.delete(req.uri().path())?;
            (StatusCode::OK, None)
        }
        &Method::HEAD => {
            // Like GET, except do not return the value
            match store.exists(req.uri().path()) {
                Ok(true) => (StatusCode::OK, None),
                Ok(false) => (StatusCode::NOT_FOUND, None),
                Err(error) => return Err(error.into()),
            }
        }
        &Method::OPTIONS => return handle_options_request(&req),
        // No other methods are currently supported
        _ => (StatusCode::METHOD_NOT_ALLOWED, None),
    };

    Ok(http::Response::builder().status(status).body(body)?)
}