use anyhow::Result;
use spin_sdk::{
    config,
    http::{Request, Response},
    http_component,
};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use http::{StatusCode};
use jsonwebtoken::{Header as jwt_header};
use serde_json::Value;
use jsonwebtoken::{encode as jwt_encode,EncodingKey};
//use annotation_lib::annotation_secret;
//#[annotation_secret(secret1)]
//pub const PRESHARED_AUTH_HEADER_VALUE: [u8; 12] = *b"123456789876";
/// A simple Spin HTTP component.
#[http_component]
fn hello_world(req: Request) -> Result<Response> {
    let expiration_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .checked_add(Duration::from_secs(3600)) // Adds 1 hour
    .expect("Overflow when adding duration")
    .as_secs();

    //println!("{:?}", req);
    let (_parts, body) = req.into_parts();
    //let response = format!("My {} likes to eat {}", std::env::var("PET")?, std::env::var("FOOD")?);
    let secret_key = config::get("jwt_key").expect("Failed to acquire dotenv from spin.toml");
    //println!("{:?}",secret_key);
    
    let claims_string = match &body {
        Some(bytes) => {
            // Convert Bytes to Vec<u8> here. The exact method depends on the type of `Bytes`.
            // For example, if `Bytes` is from the `bytes` crate, you might do:
            let bytes_vec = bytes.to_vec();
    
            // Now, convert Vec<u8> to String
            String::from_utf8(bytes_vec).unwrap_or_else(|err| {
                // Handle the error case where the Vec<u8> can't be converted to a String
                eprintln!("Invalid UTF-8 sequence: {}", err);
                String::new() // or handle the error differently
            })
        },
        None => {
            // Handle the case where `body` is None
            String::new() // or a different default string or error handling
        }
    };


    
    let new_uri_str = "http://130.245.42.183:5000/check-header";
    let new_uri = new_uri_str.parse::<http::Uri>().map_err(|e| http::Error::from(e))?;  
    //println!("claims_string {}",claims_string);                              
    let mut claims: serde_json::Value = serde_json::from_str(&claims_string).unwrap();
    
    if claims.is_object() {
        claims.as_object_mut().unwrap().insert("exp".to_string(), Value::from(expiration_time));
    }
    let encoding_key = EncodingKey::from_secret(secret_key.as_ref());
    let token = jwt_encode(&jwt_header::default(), &claims, &encoding_key).unwrap();
    let concatenated_header = format!("{}{}", "Bearer ", token.clone());
    let request_builder = http::Request::builder()
    .method("POST")
    .header("Authorization",concatenated_header)
    .uri(new_uri);
    //println!("{:?}",token);
    
    let res = spin_sdk::outbound_http::send_request(
        request_builder
            .body(Some(body.unwrap_or_else(bytes::Bytes::new)))?,
    )?;
    let cloned_body = res.body().clone();
    Ok(http::Response::builder().status(StatusCode::OK).body(cloned_body)?)
}
