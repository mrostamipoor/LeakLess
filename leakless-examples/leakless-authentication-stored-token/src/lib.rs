use anyhow::Result;
use spin_sdk::{
    config,
    http::{Request, Response},
    http_component,
};

use serde_json::{Value, Error,json};
fn id_to_uuid(path: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        &path[0..8],
        &path[8..12],
        &path[12..16],
        &path[16..20],
        &path[20..]
    )
}

fn parse_page_id(id: &str) -> Option<String> {
    if !id.is_empty() {
        let raw_id = id.replace("-", "");
        let raw_id = &raw_id[raw_id.len() - 32..];
        Some(id_to_uuid(raw_id))
    } else {
        None
    }
}

#[http_component]
fn send_outbound(req: Request) -> Result<Response> {
    let (_parts, body) = req.into_parts();
    let claims_string = match &body {
        Some(bytes) => {
            let bytes_vec = bytes.to_vec();
    
            String::from_utf8(bytes_vec).unwrap_or_else(|err| {
                eprintln!("Invalid UTF-8 sequence: {}", err);
                String::new()
            })
        },
        None => {
            String::new() 
        }
    };
    let parsed_json: Result<Value, Error> = serde_json::from_str(&claims_string);
    let binding = parsed_json.unwrap();
    let parsed_json=binding.as_object().unwrap();
    let ancestor_id = parsed_json.get("ancestorId").unwrap().as_str().unwrap();
    let ancestor_id_parsed=parse_page_id(ancestor_id).unwrap();
    let query= parsed_json.get("query").unwrap().as_str().unwrap();
    let limit= parsed_json.get("limit").unwrap().as_str().unwrap();
    let additional_text= parsed_json.get("additionalText").unwrap().as_str().unwrap();
    let json_body = json!({
        "ancestorId": ancestor_id_parsed,
        "query": query,
        "limit": limit,
        "additionalText":additional_text,
    });
    let request_body = serde_json::to_string(&json_body)
    .map(|body| bytes::Bytes::from(body))
    .unwrap_or_else(|_| bytes::Bytes::new());
    let api_key = config::get("api_key").expect("Failed to acquire dotenv from spin.toml");
    let mut res = spin_sdk::outbound_http::send_request(
        http::Request::builder()
            .method("POST")
            .header("api-key",api_key)
            .header("Content-Type","application/json")
            .uri("http://0.0.0.0:5000/search")
            .body(Some(request_body))?,
    )?;
    res.headers_mut()
        .insert("spin-component", "rust-outbound-http".try_into()?);
    Ok(res)
}
