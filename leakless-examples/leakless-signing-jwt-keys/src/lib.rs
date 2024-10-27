use anyhow::Result;
use spin_sdk::{
    http::{Request, Response},
    http_component,
};
use http::{StatusCode};
use jsonwebtoken::{Header as jwt_header};
#[http_component]
fn hello_world(req: Request) -> Result<Response> {
    let (_parts, body) = req.into_parts();
    let claims_string = match &body {
        Some(bytes) => {
            let bytes_vec = bytes.to_vec();
    
            // Now, convert Vec<u8> to String
            String::from_utf8(bytes_vec).unwrap_or_else(|err| {
                // Handle the error case where the Vec<u8> can't be converted to a String
                eprintln!("Invalid UTF-8 sequence: {}", err);   
                String::new() 
            })
        },
        None => {
            String::new() 
        }
    };
    
    let new_uri_str = "http://0.0.0.0:5000/check-header";
    let new_uri = new_uri_str.parse::<http::Uri>().map_err(|e| http::Error::from(e))?;                                
    let header = jwt_header::default();
    let header_json = serde_json::to_string(&header).unwrap(); // Serialize to JSON string
    let encoded_header = base64::encode(header_json.as_bytes());
    let claims: serde_json::Value = serde_json::from_str(&claims_string).unwrap();
    let claims_json = serde_json::to_string(&claims).unwrap();

// Convert the JSON string to a byte slice and encode it to base64
    let encoded_payload = base64::encode(claims_json.as_bytes());
    let token = format!("Bearer {}.{}.{}", encoded_header, encoded_payload, "signature");
    let request_builder = http::Request::builder()
    .method("POST")
    .header("Authorization",token)
    .uri(new_uri);


    let res = spin_sdk::outbound_http::send_request(
        request_builder
            .body(Some(body.unwrap_or_else(bytes::Bytes::new)))?,
    )?;
    
    let cloned_body = res.body().clone();
    Ok(http::Response::builder().status(StatusCode::OK).body(cloned_body)?)
}
