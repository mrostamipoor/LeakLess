use anyhow::Result;
use http::{StatusCode};
use spin_sdk::{
    http::{Request, Response},
    http_component,
};


fn verify_key(ukey_key: &str) -> Result<Response> {
    // POST request handling
    let new_uri_str = "http://0.0.0.0:5000/verify-key";
    let new_uri = new_uri_str.parse::<http::Uri>().map_err(|e| http::Error::from(e))?;
    let request_builder = http::Request::builder()
        .method("GET")
        .header("ukey-key",ukey_key)
        .uri(new_uri);

    let res = spin_sdk::outbound_http::send_request(
        request_builder
            .body(None)?,
    )?;

    let cloned_body = res.body().clone();
    Ok(http::Response::builder().status(StatusCode::OK).body(cloned_body)?)
}
#[http_component]
fn handle_request(req: Request) -> Result<Response> {
    let ukey_key = req.headers().get("unkey-key").and_then(|v| v.to_str().ok());
    if ukey_key.is_none() {
        return Ok(http::Response::builder()
        .status(403)
        .body(Some("You should provide a key for verification".into()))?);
    }
    let ukey_key = ukey_key.unwrap().trim_start_matches("Bearer ");
    let (status, body)=match verify_key(ukey_key) {
        Ok(response) => {
            let status = response.status();
            let body = Some(response.body().clone()); 
            (status, body)
        },
        Err(_) => {
            // Handle error, for example, return a 500 internal server error
            (StatusCode::INTERNAL_SERVER_ERROR, None)
        }
    };


    Ok(http::Response::builder().status(status).body(body.unwrap())?)
}
