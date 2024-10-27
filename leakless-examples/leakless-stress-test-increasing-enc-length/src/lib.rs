use anyhow::Result;
use http::{StatusCode};
use spin_sdk::{
    config,
    http::{Request, Response},
    http_component,
};
use std::collections::HashMap;
use serde_json::Value;
use http::HeaderMap;


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
    if let Some(user_agent) = headers.get("User-Agent") {
        if let Ok(ua_string) = user_agent.to_str() {
            return BANNED_UA.iter().any(|&banned| ua_string.contains(banned));
        }
    }

    false
}


#[http_component]
fn handle_request(req: Request) -> Result<Response> {
    // Open the default key-value store
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


   

    
    let new_uri_str = "http://130.245.42.183:5000/check-header";
    let new_uri = new_uri_str.parse::<http::Uri>()?;

    let request_builder = http::Request::builder()
        .method(req.method())
        .uri(new_uri);

    let (_parts, body) = req.into_parts();
    let claims_string = match body {
        Some(bytes) => {
            // Convert Bytes to Vec<u8> and then to String
            String::from_utf8(bytes.to_vec()).unwrap_or_else(|err| {
                eprintln!("Invalid UTF-8 sequence: {}", err);
                String::new()
            })
        },
        None => String::new()
    };

    let claims: Value = serde_json::from_str(&claims_string).unwrap();

    let mut stored_values = HashMap::new();
    for i in 1..=6 {
        let key = format!("variable_stored{}", i);
        let value = config::get(&key).expect("Failed to acquire value from config");
        stored_values.insert(key, value);
    }
    for i in 1..=6 {
        let json_key = format!("variable{}", i);
        let json_value = claims.get(&json_key)
                               .and_then(|v| v.as_str())
                               .unwrap();
        let config_key = format!("variable_stored{}", i);
        if let Some(stored_value) = stored_values.get(&config_key) {
            if json_value != stored_value {
                return Ok(http::Response::builder()
                .status(403)
                .header("CONTENT_TYPE", "text/plain")
                .body(Some("not value".into()))?);
            }
        }
    }

    

    let res = spin_sdk::outbound_http::send_request(
        request_builder.body(None)?
    )?;

    let cloned_body = res.body().clone();
    return Ok(http::Response::builder().status(StatusCode::OK).body(cloned_body)?);
}
