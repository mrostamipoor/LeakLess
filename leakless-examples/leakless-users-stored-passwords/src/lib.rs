use anyhow::Result;
use spin_sdk::{
    config,
    http::{Request, Response},
    http_component,
};


struct PostData {
    id: String,
    text: String,
    username: String,
    password: String,
}
use serde_json::{json};

#[allow(dead_code)]
fn extract_text(input: &[u8]) -> String {
    // Simple UTF-8 text extraction. Real implementation might be more complex.
    String::from_utf8_lossy(input).into_owned()
}



/// Send an HTTP request and return the response.
#[http_component]
fn send_outbound(_req: Request) -> Result<Response> {

    let post_username = config::get("username").expect("Failed to acquire dotenv from spin.toml");
    let post_password = config::get("password").expect("Failed to acquire dotenv from spin.toml");
    let uri_post = "http://0.0.0.0:5000/post-response";

    let post_data = PostData {
        id: "text-file".to_string(),
        text: "his text data!".to_string(),
        username: post_username,
        password: post_password,
    };
    let json_value = json!({
        "id": post_data.id,
        "text": post_data.text,
        "username": post_data.username,
        "password": post_data.password,
    });

    let request_body = serde_json::to_string(&json_value)
    .map(|body| bytes::Bytes::from(body))
    .unwrap_or_else(|_| bytes::Bytes::new()); 

    let res = spin_sdk::outbound_http::send_request(
        http::Request::builder()
            .method("POST")
            .header("Content-Type","application/json")
            .uri(uri_post)
            .body(Some(request_body))?,
    )?;

    Ok(res)
}
