use anyhow::Result;
//use std::str::from_utf8;
use spin_sdk::{config,
    http::{Request, Response},
    http_component,
};
extern crate base64;



use hmac_sha256::{HMAC, Hash};
//use std::hash::Hash;
fn sign(key: &[u8], message: &str) -> [u8; 32] {
    HMAC::mac(message.as_bytes(), key)
}
/// A simple Spin HTTP component.
#[http_component]
fn hello_world(_req: Request) -> Result<Response> {
    let s3_access = config::get("s3_access").expect("Failed to acquire dotenv from spin.toml");
    let s3_secret = config::get("s3_secret").expect("Failed to acquire dotenv from spin.toml");
    let x_amz_content_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = format!("{}.s3.amazonaws.com", "demobucket-maryam001");
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}",
        host, x_amz_content_sha256, amz_date
    );

    let url = "https://demobucket-maryam001.s3.amazonaws.com/09vke4d306p81.jpg";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n\n{}\n{}",
        "GET",
        "/09vke4d306p81.jpg",
        "",
        canonical_headers,
        signed_headers,
        x_amz_content_sha256
    );
    
    //println!("canonical_request {:?}",canonical_request);
    
    let credential_date = &amz_date[..8];
    let credential_scope = format!("{}/{}/{}/aws4_request", credential_date, "us-east-1", "s3");
    
    let canonical_request_hash = hex::encode(Hash::hash(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );
    let aws4_secret = format!("AWS4{}", s3_secret).into_bytes();
    let date_key = sign(&aws4_secret, credential_date);
    let region_key = sign(&date_key, "us-east-1");
    let service_key = sign(&region_key, "s3");
    let signing_key = sign(&service_key, "aws4_request");
    //println!("string_to_sign {:?}",string_to_sign);
    let signature = hex::encode(sign(&signing_key, &string_to_sign));
    let authorization=format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        s3_access, credential_scope, signed_headers, signature
    );
    //println!("signature {:?}",string_to_sign);
    //println!("output {:?}",output); 
  /* #[annotation_secret(secret1)]
    pub static var: [u8; 24] = *b"Thid is sensitive value!";

    #[annotation_secret(secret2)]
    pub static FIRST1: [u8; 12] = *b"Bearer ya29.bHES6ZRVmB7fkLtd1XTmq6mo0S1wqZZi3-Lh_s-6Uw7p8vtgSwg";
    
    Ok(http::Response::builder()
        .status(200)
        .header("Authorization-secret",  encode(FIRST1))
        .body(Some(encode(var).into()))?)*/
        //use chrono::{Datelike, Timelike, Utc};

        //let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        //let host = format!("{}.s3.amazonaws.com", "spinwasmtime");
        //println!("ddd {:?}", "res");

        let mut res = spin_sdk::outbound_http::send_request(
            http::Request::builder()
                .method("GET")
                .header("X-Amz-Content-Sha256",x_amz_content_sha256)
                .header("host",  host)
                //.header("test",  "LEAKLESS_TEST_LEAKLESS")
                .header("x-amz-date",  amz_date)
                .header("Authorization", authorization)
                .uri(url)
                .body(Some("".into()))?,
        )?;
        
        res.headers_mut()
            .insert("spin-component", "rust-outbound-http".try_into()?);
        //println!("ddd {:?}", res);
        Ok(res)

}