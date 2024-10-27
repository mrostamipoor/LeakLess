use hyper::server::conn::AddrStream;
use hyper::{Body, Request, Method,Response, Server, StatusCode,Client};
use hyper::service::{service_fn, make_service_fn};
use hyper::{
    header::CONTENT_LENGTH,
};
use std::fs;
use http::header::CONTENT_TYPE;
use std::str::FromStr;
use std::path::Path;
use std::{convert::Infallible, net::SocketAddr};
use std::net::IpAddr;
use std::io::BufReader;
use std::fs::File;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use jsonwebtoken::{decode  as jwt_decode, encode as jwt_encode,decode_header, Validation, EncodingKey, DecodingKey};
use lazy_static::lazy_static;
use base64::{encode, decode};
use hyper_trust_dns::{TrustDnsResolver};
use hyper_trust_dns::TrustDnsHttpConnector;
use hyper::Error;
use hyper::header::{HOST};
use hyper::header::{HeaderMap, HeaderValue, HeaderName};
use hyper::http::header::{InvalidHeaderValue, ToStrError};
use hyper::http::uri::InvalidUri;
use hyper::client::HttpConnector;
use hudsucker::{
    async_trait::async_trait,
    decode_request,
    certificate_authority::RcgenAuthority,
    HttpContext, HttpHandler, RequestOrResponse,
    tokio_tungstenite::tungstenite::Message,
    *,
};
use std::collections::HashMap;
use std::str;
use rustls_pemfile as pemfile;
use tracing::*;
use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Key // Or `Aes128Gcm`
};
use std::io::{BufRead};

lazy_static! {
    static ref ARGS: Vec<String> = {
        let file = File::open("./spin.toml").unwrap();
        let reader = BufReader::new(file);
        let mut lists: Vec<String>=vec![];
        for line in reader.lines() {
           let line_copy=line.unwrap().clone();           
            if line_copy.contains(&"route"){
                let splitted: Vec<&str>=line_copy.split("=").collect();
                let splitted: Vec<&str>=splitted[1].split("=").collect();
                let splitted = splitted[0].replace("\"", "");
                let splitted = splitted.replace(" ", "");
                lists.push(splitted);
            }
        }
        lists
 };
 static ref HASHMAP_PATHS: HashMap<String, String> = {
    let file = File::open("spin.toml").unwrap();
    let reader = BufReader::new(file);

    let mut component_ids = HashMap::new();
    let component_regex = regex::Regex::new(r#"^\s*id\s*=\s*"([^"]+)""#).unwrap();

    let mut current_id = String::new();
    let mut in_component_section = false;
    let mut _current_route = String::new();

    for line in reader.lines() {
        let line = line.unwrap();
        if let Some(captures) = component_regex.captures(&line) {
            current_id = captures.get(1).unwrap().as_str().to_string();
            in_component_section = true;
        } else if in_component_section && line.starts_with("route =") {
            _current_route = line.splitn(2, "route = ").nth(1).unwrap().trim_matches('"').to_string();
            component_ids.insert(_current_route.clone(), current_id.clone());
            in_component_section = false;
        }
    }
    component_ids
};
static ref HASHMAP_JWT_VERIFY: HashMap<String, String> = {
    let mut hashmap = HashMap::new();

    match File::open("jwt_verify") {
        Ok(file) => {
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line.expect("Failed to read line");
                let parts: Vec<&str> = line.split(":::").collect();
                if parts.len() == 2 {
                    let key = parts[0].to_string();
                    let value = parts[1].to_string();

                    hashmap.insert(key, value);
                } else {
                    eprintln!("Skipping invalid line: {}", line);
                }
            }
        }
        Err(_) => {
            // Handle the case when the file does not exist
            eprintln!("No function has requested JWT token verification!");
        }
    }

    hashmap
};
static ref HASHMAP_JWT_SIGN: HashMap<String, String> = {
    let mut hashmap = HashMap::new();

    match File::open("jwt_sign") {
        Ok(file) => {
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line.expect("Failed to read line");
                let parts: Vec<&str> = line.split(":::").collect();
                if parts.len() == 2 {
                    let key = parts[0].to_string();
                    let value = parts[1].to_string();

                    hashmap.insert(key, value);
                } else {
                    eprintln!("Skipping invalid line: {}", line);
                }
            }
        }
        Err(_) => {
            // Handle the case when the file does not exist
            eprintln!("No function has requested JWT token signing!");
        }
    }

    hashmap
};

static ref HASHMAP_SIGN_REQUEST: HashMap<String, String> = {
    let mut hashmap = HashMap::new();

    match File::open("sign_request") {
        Ok(file) => {
            let reader = BufReader::new(file);
            
            for line in reader.lines() {
                let line = line.expect("Failed to read line");
                let parts: Vec<&str> = line.split(":::").collect();
                if parts.len() == 2 {
                    let key = parts[0].to_string();
                    let value = parts[1].to_string();

                    hashmap.insert(key, value);
                } else {
                    eprintln!("Skipping invalid line: {}", line);
                }
            }
        }
        Err(_) => {
            // Handle the case when the file does not exist
            eprintln!("No function has requested request signing!");
        }
    }

    hashmap
};
static ref HASHMAP_KEYS: HashMap<String, Vec<u8>> = {
    let mut hashmap = HashMap::new();
    let file = File::open("key_moduleid").expect("Failed to open file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let parts: Vec<&str> = line.split(":::").collect();
        if parts.len() == 2 {
            let key = parts[0].to_string();
            //println!("encoded key in inout: {}", parts[1].trim());
            let value = decode(parts[1].trim())
                .expect("Failed to decode binary data");

            hashmap.insert(key, value);
        } else {
            println!("Skipping invalid line: {}", line);
        }
    }
    hashmap
};
static ref  FRONTEND: FrontEnd<TrustDnsHttpConnector> = {
    FrontEnd::new(
        hyper::Client::builder().build::<_, hyper::Body>(TrustDnsResolver::default().into_http_connector()),
    )
};

static ref FRONTEND_SECURE: FrontEndSecure = {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    FrontEndSecure::new(client)
};



}

extern crate tracing;

#[derive(Debug)]
pub enum InOutError {
    InvalidUri(InvalidUri),
    HyperError(Error),
    ForwardHeaderError,
    UpgradeError(String),
}

impl From<Error> for InOutError {
    fn from(err: Error) -> InOutError {
        InOutError::HyperError(err)
    }
}

impl From<InvalidUri> for InOutError {
    fn from(err: InvalidUri) -> InOutError {
        InOutError::InvalidUri(err)
    }
}

impl From<ToStrError> for InOutError {
    fn from(_err: ToStrError) -> InOutError {
        InOutError::ForwardHeaderError
    }
}

impl From<InvalidHeaderValue> for InOutError {
    fn from(_err: InvalidHeaderValue) -> InOutError {
        InOutError::ForwardHeaderError
    }
}
fn create_proxied_response<B>( response: Response<B>) -> Response<B> {
    response
}

fn forward_uri<B>(forward_url: &str, req: &Request<B>) -> String {

    let split_url = forward_url.split('?').collect::<Vec<&str>>();
    let mut base_url: &str = split_url.get(0).unwrap_or(&"");
    let forward_url_query: &str = split_url.get(1).unwrap_or(&"");

    let path2 = req.uri().path();

    if base_url.ends_with('/') {
        let mut path1_chars = base_url.chars();
        path1_chars.next_back();

        base_url = path1_chars.as_str();
    }

    let total_length = base_url.len()
        + path2.len()
        + 1
        + forward_url_query.len()
        + req.uri().query().map(|e| e.len()).unwrap_or(0);

    let mut url = String::with_capacity(total_length);

    url.push_str(base_url);
    url.push_str(path2);

    if !forward_url_query.is_empty() || req.uri().query().map(|e| !e.is_empty()).unwrap_or(false) {
        url.push('?');
        url.push_str(forward_url_query);

        if forward_url_query.is_empty() {

            url.push_str(req.uri().query().unwrap_or(""));
        } else {

            let request_query_items = req.uri().query().unwrap_or("").split('&').map(|el| {
                let parts = el.split('=').collect::<Vec<&str>>();
                (parts[0], if parts.len() > 1 { parts[1] } else { "" })
            });

            let forward_query_items = forward_url_query
                .split('&')
                .map(|el| {
                    let parts = el.split('=').collect::<Vec<&str>>();
                    parts[0]
                })
                .collect::<Vec<_>>();

            for (key, value) in request_query_items {
                if !forward_query_items.iter().any(|e| e == &key) {
                    url.push('&');
                    url.push_str(key);
                    url.push('=');
                    url.push_str(value);
                }
            }

            if url.ends_with('&') {
                let mut parts = url.chars();
                parts.next_back();

                url = parts.as_str().to_string();
            }
        }
    }


    url.parse().unwrap()
}
#[allow(dead_code)]
fn encrypt_gcm(key: &Key<Aes256Gcm>, nonce:&[u8], message: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let nonce = GenericArray::from_slice(nonce); 
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, message)?;
    Ok(ciphertext.to_vec())
}

#[allow(dead_code)]
fn decrypt_gcm(key: &Key<Aes256Gcm>, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let nonce = GenericArray::from_slice(nonce); 
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(nonce, ciphertext)?;
    Ok(plaintext.to_vec())
}
fn create_proxied_request<B>(
    _client_ip: IpAddr,
    forward_url: &str,
    mut request: Request<B>,
) -> Result<Request<B>, InOutError> {
    let uri: hyper::Uri = forward_uri(forward_url, &request).parse()?;
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(uri.host().unwrap())?);

    *request.uri_mut() = uri;

    Ok(request)
}

pub async fn call<'a, T: hyper::client::connect::Connect + Clone + Send + Sync + 'static>(
    client_ip: IpAddr,
    forward_uri: &str,
    request: Request<Body>,
    client: &'a Client<T>,
) -> Result<Response<Body>, InOutError> {

    let proxied_request = create_proxied_request(
        client_ip,
        forward_uri,
        request,
    )?;
    let response = client.request(proxied_request).await?;

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        Ok(response)
    } else {
        let proxied_response = create_proxied_response(response);
        Ok(proxied_response)
    }
}


use hyper_tls::HttpsConnector;

pub struct FrontEndSecure {
    client: Client<HttpsConnector<hyper::client::HttpConnector>>,
}

impl FrontEndSecure {
    pub fn new(_client: Client<HttpsConnector<HttpConnector>>) -> Self {
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);
        Self { client }
    }

    pub async fn call_secure(
        &self,
        client_ip: IpAddr,
        forward_uri: &str,
        request: Request<Body>,
    ) -> Result<Response<Body>, InOutError> {
        call::<HttpsConnector<hyper::client::HttpConnector>>(
            client_ip,
            forward_uri,
            request,
            &self.client,
        )
        .await
    }
}


pub struct FrontEnd<T: hyper::client::connect::Connect + Clone + Send + Sync + 'static> {
    client: Client<T>,
}

impl<T: hyper::client::connect::Connect + Clone + Send + Sync + 'static> FrontEnd<T> {
    pub fn new(client: Client<T>) -> Self {
        Self { client }
    }


    pub async fn call(
        &self,
        client_ip: IpAddr,
        forward_uri: &str,
        request: Request<Body>,
    ) -> Result<Response<Body>, InOutError> {
        call::<T>(client_ip, forward_uri, request, &self.client).await
    }


}

#[cfg(feature = "__bench")]
pub mod benches {
    pub fn hop_headers() -> &'static [crate::HeaderName] {
        &*super::HOP_HEADERS
    }

    pub fn create_proxied_response<T>(response: crate::Response<T>) {
        super::create_proxied_response(response);
    }

    pub fn forward_uri<B>(forward_url: &str, req: &crate::Request<B>) {
        super::forward_uri(forward_url, req);
    }

    pub fn create_proxied_request<B>(
        client_ip: crate::IpAddr,
        forward_url: &str,
        request: crate::Request<B>,
    ) {
        super::create_proxied_request(client_ip, forward_url, request).unwrap();//, upgrade_type
    }
}
const IV: [u8; 16] = [45, 67, 89, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56];
fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize128,
            key,
            &IV,
            blockmodes::PkcsPadding);


    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true);

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            Ok(BufferResult::BufferUnderflow) => break,
            Ok(BufferResult::BufferOverflow) => { }
            Err(_) => todo!()
        }
    }

    Ok(final_result)
}
fn debug_request(req: Request<Body>) -> Result<Response<Body>, Infallible>  {
    let body_str = format!("{:?}", req);
    Ok(Response::new(Body::from(body_str)))
}
fn unauthorized_response() -> Result<Response<Body>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from("Your JWT token is invalid or missing"))
        .unwrap()) 
}


async fn handle_incoming_requests(client_ip: IpAddr, req: Request<Body>) -> Result<Response<Body>, Infallible> {

    static PATH_TO_CHECK: &str = "/...";
    static LEAKLESS_PREFIX: &str = "LEAKLESS_";
    static LEAKLESS_SUFFIX: &str = "_LEAKLESS";

    let path = req.uri().path().to_string();
    let string_check=&PATH_TO_CHECK.to_string();
    let check = ARGS.contains(string_check);
    if ARGS.contains(&path) || check {
        let mut secret_headers = HashMap::new();
        let module_id = if check {
            HASHMAP_PATHS.get(string_check).unwrap()
        } else {
            HASHMAP_PATHS.get(&path).unwrap()
        };
        let crypto_key_value = HASHMAP_KEYS.get(module_id).unwrap();
        //It does check for JWT verification if the user register for that!
        if let Some(secret_key) = HASHMAP_JWT_VERIFY.get(module_id) {
            if let Some(authorization_header) = req.headers().get("Authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.split_whitespace().nth(1)) {
                
                match decode_header(authorization_header) {
                    Ok(header) => {
                        let decoding_key = DecodingKey::from_secret(secret_key.as_ref());
                        let mut validation = Validation::new(header.alg);
                        validation.validate_exp = false;
        
                        if jwt_decode::<HashMap<String, serde_json::Value>>(authorization_header, &decoding_key, &validation).is_err() {
                            eprintln!("JWT validation error");
                            return unauthorized_response();
                        }
                    },
                    Err(_) => {
                        eprintln!("JWT decode error");
                        return unauthorized_response();
                    },
                }
            } else {
                eprintln!("Authorization header missing or invalid");
                return unauthorized_response();
            }
        }
            for (key, value) in req.headers() {
                if let Ok(value_str) = value.to_str() {
                    if value_str.contains(LEAKLESS_PREFIX) && value_str.contains(LEAKLESS_SUFFIX) {
                        let start_index = value_str.find(LEAKLESS_PREFIX).unwrap() + LEAKLESS_PREFIX.len();
                        let end_index = value_str.find(LEAKLESS_SUFFIX).unwrap();
                        let value_slice = &value_str[start_index..end_index];
                        //println!("value_slice {:?}", value_slice);
                        let result = value_slice.as_bytes().to_vec();                                
                        let encrypt_value = encrypt(&result, crypto_key_value).ok().unwrap();
                        //println!("crypto_key_value in in/out {:?}", crypto_key_value);
                        let encoded = encode(encrypt_value);
                        let encoded_with_prefix = format!("{}{}{}", LEAKLESS_PREFIX, encoded, LEAKLESS_SUFFIX);
                        //println!("encoded_with_prefix {:?}", encoded_with_prefix);
                        secret_headers.insert(
                                key.clone(),
                                encoded_with_prefix,
                            );
                        }

                }

            }
        let (mut parts, body) = req.into_parts();
        
        for (header, value) in &secret_headers {
            parts.headers.remove(header);
            parts.headers.append(header , HeaderValue::from_str(&value.to_string()).unwrap());

        }
        let body_bytes = hyper::body::to_bytes(body).await.unwrap();

        match std::str::from_utf8(&body_bytes) {
            Ok(body_str) => {
                let mut total_string = String::new();
                               
                if body_str.contains(LEAKLESS_PREFIX) && body_str.contains(LEAKLESS_SUFFIX) {

                    let mut replaced_body = String::new();
                    let mut search_start_index = 0;
                    let mut last_end_index = 0;
                
                    while let (Some(start_index), Some(end_index)) = (
                        body_str[search_start_index..].find(LEAKLESS_PREFIX),
                        body_str[search_start_index..].find(LEAKLESS_SUFFIX),
                    ) {
                        let real_start_index = search_start_index + start_index + LEAKLESS_PREFIX.len();
                        let real_end_index = search_start_index + end_index;
                
                        let extracted_value = &body_str[real_start_index..real_end_index];
                
                        // Decrypt the extracted value (as in your current code)
                        let key = HASHMAP_KEYS.get(module_id).unwrap();
                        let encrypt_value = encrypt(extracted_value.as_bytes(), key).ok().unwrap();
                        let encoded = encode(encrypt_value);
                        let encoded_with_prefix = format!("{}{}{}", LEAKLESS_PREFIX, encoded, LEAKLESS_SUFFIX);
                        // Accumulate the result
                        replaced_body.push_str(&body_str[last_end_index..search_start_index + start_index]);
                        replaced_body.push_str(&encoded_with_prefix);
                        last_end_index = real_end_index + LEAKLESS_SUFFIX.len();
                
                        // Update the search_start_index to search for the next occurrence
                        search_start_index = last_end_index;
                    }
                
                    // Append any remaining part of the original body after the last encrypted part
                    replaced_body.push_str(&body_str[last_end_index..]);
                    parts.headers.remove(CONTENT_LENGTH);
                    let content_length_header = HeaderValue::from_str(&replaced_body.len().to_string()).unwrap();
                    parts.headers.insert(CONTENT_LENGTH, content_length_header);
                    let req = Request::from_parts(parts, hyper::Body::from(replaced_body));
                    match FRONTEND.call(client_ip, "http://0.0.0.0:3000", req).await {
                        Ok(response) => Ok(response),
                        Err(_error) => {
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::empty())
                                .unwrap())
                        }
                    }
                }                        
                else {
                    total_string.push_str(body_str);
                    let req = Request::from_parts(parts, Body::from(total_string));
                    match FRONTEND.call(client_ip, "http://0.0.0.0:3000", req).await {
                        Ok(response) => Ok(response),
                        Err(_error) => {
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::empty())
                                .unwrap())
                        }
                    }

                }
            },
            Err(_) => {
                let req = Request::from_parts(parts, Body::from(body_bytes));
                match FRONTEND.call(client_ip, "http://0.0.0.0:3000", req).await {
                    Ok(response) => Ok(response),
                    Err(_error) => {
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::empty())
                            .unwrap())
                    }
                }
            }
            

        } 
    }
    else {
           debug_request(req)
    }
}

#[derive(Clone)]
pub struct OutgoingRequestsHandler;

fn decrypt(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize128,
            key,
            &IV,
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true);
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            Ok(BufferResult::BufferUnderflow) => break,
            Ok(BufferResult::BufferOverflow) => { },
            //Err(_) => todo!()
            Err(_) => { }
        }
    }

    Ok(final_result)
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}



#[derive(Clone)]
struct LogHandler;

#[async_trait]
  impl HttpHandler for OutgoingRequestsHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // Define some static constants
        static LEAKLESS_PREFIX: &str = "LEAKLESS_";
        static LEAKLESS_SUFFIX: &str = "_LEAKLESS";
        // Decode the incoming request
        let req = decode_request(req).unwrap();
        let head1 = req.headers().clone();
        let mut module_id_tmp = "";
    
        // Extract the 'LeakLess-Header' value if the request method is not CONNECT
        if req.method() != Method::CONNECT {
            module_id_tmp = head1
                .get("LeakLess-Header")
                .expect("failed")
                .to_str()
                .unwrap();
        }
    
        let module_id = module_id_tmp.clone();
        let req_uri = req.uri().clone().to_string();
        let method = req.method().clone().to_string();
        let head = req.headers().clone();
        let head_string = format!("{:?}", head);
        let (mut parts, body) = req.into_parts();
        let mut secret_headers = HashMap::new();
    
        // Convert the request body into bytes and then into a string
        let body_bytes = hyper::body::to_bytes(body).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
    
        // Process headers and potentially replace them
        if head_string.contains(LEAKLESS_PREFIX) || head_string.contains("Authorization")
        || head_string.contains("authorization"){
            for (key, value) in &head {
                let value = value.to_str().unwrap();
                if value.contains(LEAKLESS_PREFIX) && value.contains(LEAKLESS_SUFFIX) {
                    // Decrypt a specific header value
                    let start_index = value.find(LEAKLESS_PREFIX).unwrap() + LEAKLESS_SUFFIX.len();
                    let end_index = value.find(LEAKLESS_SUFFIX).unwrap();
                    let extracted_value = &value[start_index..end_index];
                    let decoded = decode(extracted_value.as_bytes()).unwrap();
                    let ciphertext: &[u8] = &decoded;
                    let crypto_key_value = HASHMAP_KEYS.get(module_id).unwrap();
                    let decrypted_data = decrypt(ciphertext, crypto_key_value).ok().unwrap();
                    let decrypted_string = String::from_utf8(decrypted_data).unwrap();
                    let before_encrypted_part = &value[..start_index - LEAKLESS_PREFIX.len()];
                    let after_encrypted_part = &value[end_index + LEAKLESS_SUFFIX.len()..];
                    let new_header_value =
                        format!("{}{}{}", before_encrypted_part, decrypted_string, after_encrypted_part);
                    secret_headers.insert(key.clone(), new_header_value);
                }
    
                let key_tmp = key.clone();
                if (key_tmp == "Authorization" || key_tmp == "authorization") && !head_string.contains("AWS4-HMAC-SHA256") && HASHMAP_JWT_SIGN.contains_key(module_id)  {
                    // Sign JWT token
                    let token = value.split(" ").nth(1).unwrap();
                    let secret_key = HASHMAP_JWT_SIGN.get(module_id).unwrap(); //here
                    let header = decode_header(token).unwrap();
                    let mut parts = token.split(".");
                    let payload = parts.nth(1).unwrap();
    
                    let decoded_payload = base64::decode(payload).unwrap();
                    let claims_string = String::from_utf8(decoded_payload).unwrap();
                    let claims: serde_json::Value = serde_json::from_str(&claims_string).unwrap();
                    let encoding_key = EncodingKey::from_secret(secret_key.as_ref());
                    let token = jwt_encode(&header, &claims, &encoding_key).unwrap();
                    let token = format!("Bearer {}", token);
                    secret_headers.insert(key_tmp.clone(), token);
                }
    
                if (key_tmp == "Authorization" || key_tmp == "authorization") && head_string.contains("AWS4-HMAC-SHA256") {
                    // Sign AWS S3 request
                    let value = secret_headers.get(&key_tmp).unwrap().clone();
                    let s3_secret = HASHMAP_SIGN_REQUEST.get(module_id).unwrap();
                    let datetime_str = head.get("X-Amz-Date").unwrap().to_str().unwrap();
                    let datetime = chrono::NaiveDateTime::parse_from_str(datetime_str, "%Y%m%dT%H%M%SZ")
                        .expect("Failed to parse datetime");
                    let datetime =
                        chrono::DateTime::<chrono::Utc>::from_utc(datetime, chrono::Utc);
                    let credential_start = value.find("Credential=").unwrap_or(0);
                    let credential_end = value.find(",SignedHeaders=").unwrap_or(0);
                    let header_start = value.find("SignedHeaders=").unwrap_or(0);
                    let header_end = value.find(",Signature=").unwrap_or(0);
                    let test = value.clone();
                    let mut credential_parts =
                        value[credential_start + 11..credential_end].split("/");
                    let headers_vec: Vec<String> = test[header_start + 14..header_end]
                        .split(";")
                        .map(|s| s.to_owned())
                        .collect();
                    let s3_access = credential_parts.next().unwrap_or("");
                    let region = credential_parts.nth(1).unwrap_or("");

                    // Process headers for AWS S3 signing
                    let mut new_headers_map = HeaderMap::new();
                    for header_name in headers_vec {
                        let header_value = head.get(&header_name).unwrap();
                        new_headers_map.insert(
                            HeaderName::from_str(&header_name).unwrap(),
                            header_value.clone(),
                        );
                    }

                    // Sign the AWS S3 request
                    let s = aws_sign_v4::AwsSign::new(
                        &method,
                        &req_uri,
                        &datetime,
                        &new_headers_map,
                        region,
                        &s3_access,
                        &s3_secret,
                        "s3",
                        body_str,
                    );

                    let signature = s.sign();
                    secret_headers.insert(key_tmp.clone(), signature.parse().unwrap());

                }
            }
        }
    
        // Remove the 'LeakLess-Header' from the headers
        parts.headers.remove("LeakLess-Header");
    
        // Replace original headers with modified or added secret headers
        for (header, value) in &secret_headers {
            parts.headers.remove(header);
            parts.headers.append(header, HeaderValue::from_str(&value.to_string()).unwrap());
        }
    
        let mut replaced_body = String::new();
    
        if body_str.contains(LEAKLESS_PREFIX) && body_str.contains(LEAKLESS_SUFFIX) {
            // Process the request body for encrypted data and decrypt it
            let crypto_key_value = HASHMAP_KEYS.get(module_id).unwrap();
            let mut search_start_index = 0;
            let mut last_end_index = 0;
    
            while let (Some(start_index), Some(end_index)) = (
                body_str[search_start_index..].find(LEAKLESS_PREFIX),
                body_str[search_start_index..].find(LEAKLESS_SUFFIX),
            ) {
                let real_start_index = search_start_index + start_index + LEAKLESS_PREFIX.len();
                let real_end_index = search_start_index + end_index;
    
                let extracted_value = &body_str[real_start_index..real_end_index];
                let decoded = decode(extracted_value.as_bytes()).unwrap();
                let ciphertext: &[u8] = &decoded;
                let decrypted_data = decrypt(ciphertext, crypto_key_value).ok().unwrap();
                let decrypted_data = String::from_utf8(decrypted_data).unwrap();
    
                replaced_body.push_str(&body_str[last_end_index..search_start_index + start_index]);
                replaced_body.push_str(&decrypted_data);
                last_end_index = real_end_index + LEAKLESS_SUFFIX.len();
                search_start_index = last_end_index;
            }
    
            replaced_body.push_str(&body_str[last_end_index..]);
            parts.headers.remove(CONTENT_LENGTH);
            let content_length_header =
                HeaderValue::from_str(&replaced_body.len().to_string()).unwrap();
            parts.headers.insert(CONTENT_LENGTH, content_length_header);
    
            let req = Request::from_parts(parts, Body::from(replaced_body));
            RequestOrResponse::Request(req)
        } else {
            replaced_body.push_str(body_str);
            replaced_body.push_str("\n");
    
            let req = Request::from_parts(parts, Body::from(replaced_body));
            RequestOrResponse::Request(req)
        }
    }
      async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
       res
    }
  }

#[async_trait]
impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}

#[async_trait]
impl WebSocketHandler for LogHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        Some(msg)
    }
}



use tokio::signal::ctrl_c;
use tokio::sync::oneshot;

async fn backend() {
    tracing_subscriber::fmt::init();

    let mut private_key_bytes: &[u8] = include_bytes!("LeakLess.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("LeakLess.cer");
    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut private_key_bytes)
            .expect("Failed to parse private key")
            .remove(0),
    );
    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .expect("Failed to parse CA certificate")
            .remove(0),
    );

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");
    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([0, 0, 0, 0], 3002)))
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(OutgoingRequestsHandler)
        .with_websocket_handler(LogHandler)
        .build();

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("{}", e);
    }
}

async fn frontend(bind_addr: String) {
    let addr = bind_addr.parse().expect("Could not parse ip:port.");
    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| handle_incoming_requests(remote_addr, req)))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        ctrl_c().await.expect("Failed to listen for Ctrl+C");
        tx.send(()).unwrap();
    });
    let server_task = tokio::spawn(async move {
        tokio::select! {
            _ = rx => {
                println!("Received stop signal");
            }
            result = server => {
                if let Err(e) = result {
                    eprintln!("server error: {}", e);
                }
            }
        }
    });
    server_task.await.unwrap();
}
fn delete_file_if_exists(file_path: &str) {
    if Path::new(file_path).exists() {
        if let Err(e) = fs::remove_file(file_path) {
            eprintln!("Failed to delete file: {}", e);
        }
    }
}

#[tokio::main]
async fn main() {
    let bind_addr = "0.0.0.0:3001".to_owned();

    let http_server_task = tokio::spawn(backend());
    let tcp_server_task = tokio::spawn(frontend(bind_addr));

    let _hashmap_keys=HASHMAP_KEYS.contains_key("");
    let _hashmap_paths=HASHMAP_PATHS.contains_key("");
    let _hashmap_jwtsign=HASHMAP_JWT_SIGN.contains_key("");
    let _hashmap_signkeys=HASHMAP_SIGN_REQUEST.contains_key("");
    let _hashmap_jwtverify=HASHMAP_JWT_VERIFY.contains_key("");
    let _hashmap_paths=ARGS.iter().any(|arg| arg == "/...");
    
    //delete_file_if_exists("key_moduleid");
    delete_file_if_exists("jwt_verify");
    delete_file_if_exists("jwt_sign");
    delete_file_if_exists("sign_request");
    
    let _= tokio::join!(http_server_task, tcp_server_task);
}