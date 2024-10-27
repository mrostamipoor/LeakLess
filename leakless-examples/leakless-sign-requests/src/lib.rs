use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http::{
    header::{ACCEPT_ENCODING, IF_NONE_MATCH},
    StatusCode,
};
use spin_sdk::{
    config,
    http::{Request, Response},
};
use std::{
    fs::File,
    io::Read,
    path::PathBuf,
};




const BROTLI_LEVEL: u32 = 3;
/// Brotli content encoding identifier
const BROTLI_ENCODING: &str = "br";
/// The path info header.
const PATH_INFO_HEADER: &str = "spin-path-info";
// Environment variable for the fallback path
const FALLBACK_PATH_ENV: &str = "FALLBACK_PATH";
/// Directory fallback path (trying to map `/about/` -> `/about/index.html`).
const DIRECTORY_FALLBACK_PATH: &str = "index.html";

/// Common Content Encodings
#[derive(Debug, Eq, PartialEq)]
pub enum ContentEncoding {
    Brotli,
    //Deflate, // Could use flate2 for this
    //Gzip,    // Could use flate2 for this
    None,
}

impl ContentEncoding {

    fn best_encoding(req: &Request) -> Result<Self> {
        match req.headers().get(ACCEPT_ENCODING) {
            Some(e) => {
                match e
                    .to_str()?
                    .split(',')
                    .map(|ce| ce.trim().to_lowercase())
                    .find(|ce| ce == BROTLI_ENCODING)
                {
                    Some(_) => Ok(ContentEncoding::Brotli),
                    None => Ok(ContentEncoding::None),
                }
            }
            None => Ok(ContentEncoding::None),
        }
    }
}


#[spin_sdk::http_component]
fn serve(req: Request) -> Result<Response> {
    let enc = ContentEncoding::best_encoding(&req)?;
    let _if_none_match = req
        .headers()
        .get(IF_NONE_MATCH)
        .map(|h| h.to_str())
        .unwrap_or(Ok(""))?;
    
    let path = req
        .headers()
        .get(PATH_INFO_HEADER)
        .expect("PATH_INFO header must be set by the Spin runtime")
        .to_str()?;


    FileServer::upload(path, enc)
}

struct FileServer;
impl FileServer {

    fn resolve(req_path: &str) -> Option<PathBuf> {
        // fallback to index.html if the path is empty
        let mut path = if req_path.is_empty() {
            PathBuf::from(DIRECTORY_FALLBACK_PATH)
        } else {
            PathBuf::from(req_path)
        };

        // if the path is a directory, try to read the fallback file relative to the directory
        if path.is_dir() {
            path.push(DIRECTORY_FALLBACK_PATH);
        }

        // if still haven't found a file, override with the user-configured fallback path
        if !path.exists() {
            if let Ok(fallback_path) = std::env::var(FALLBACK_PATH_ENV) {
                path = PathBuf::from(fallback_path);
            }
        }

        // return the path if it exists
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }

    /// Open the file given its path and return its content and content type header.
    fn read(path: &PathBuf, encoding: &ContentEncoding) -> Result<Bytes> {
        let mut file =
            File::open(path).with_context(|| anyhow!("cannot open {}", path.display()))?;
        let mut buf = vec![];
        match encoding {
            ContentEncoding::Brotli => {
                let mut r = brotli::CompressorReader::new(file, 4096, BROTLI_LEVEL, 20);
                r.read_to_end(&mut buf)
            }
            _ => file.read_to_end(&mut buf),
        }?;

        Ok(buf.into())
    }

    
    fn upload(
        path: &str,
        enc: ContentEncoding,
    ) -> Result<Response> {

        let body = match FileServer::resolve(path) {
            Some(path) => FileServer::read(&path, &enc).ok(),
            None => None,
        };
        
        let hash = hmac_sha256::Hash::hash(body.clone().unwrap_or_else(|| Bytes::from("")).as_ref());
        // Convert the hash to a hexadecimal string
        let hex_value=hex::encode(hash);
        let s3_access = config::get("s3_access").expect("Failed to acquire dotenv from spin.toml");
        let x_amz_content_sha256 = hex_value;
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let host = "0.0.0.0:5000";
        
        let url = "http://0.0.0.0:5000/uploadfile.txt";
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        
        let credential_date = &amz_date[..8];
        let credential_scope = format!("{}/{}/{}/aws4_request", credential_date, "us-east-1", "s3");
        let authorization=format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature=test",
            s3_access, credential_scope, signed_headers
        );

        let res = spin_sdk::outbound_http::send_request(
                http::Request::builder()
                    .method("POST")
                    .header("X-Amz-Content-Sha256",x_amz_content_sha256)
                    .header("host",  host)
                    .header("x-amz-date",  amz_date)
                    .header("Authorization", authorization)
                    .uri(url)
                    .body(Some(body.unwrap_or_else(bytes::Bytes::new)))?,
            )?;           
        if !res.status().is_success() {
            return Err(anyhow!("Failed to upload file"));
        }

        let cloned_body = res.body().clone();
        Ok(http::Response::builder().status(StatusCode::OK).body(cloned_body)?)
    }
}
