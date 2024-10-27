//! Functionality to get a prepared Spin application configuration from spin.toml.

//#![deny(missing_docs)]

/// Module to prepare the assets for the components of an application.
pub mod assets;
/// Configuration representation for a Spin application as a local spin.toml file.
pub mod config;
use spin_manifest::Variable;
#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use futures::future;
use itertools::Itertools;
use outbound_http::allowed_http_hosts::validate_allowed_http_hosts;
use path_absolutize::Absolutize;
use reqwest::Url;
use spin_manifest::{
    Application, ApplicationInformation, ApplicationOrigin, ApplicationTrigger, CoreComponent,
    HttpConfig, ModuleSource, RedisConfig, SpinVersion, TriggerConfig, WasmConfig,
};
use tokio::{fs::File,fs::metadata, io::AsyncReadExt};

use crate::{cache::Cache, digest::bytes_sha256_string, validation::validate_key_value_stores};
use config::{
    FileComponentUrlSource, RawAppInformation, RawAppManifest, RawAppManifestAnyVersion,
    RawAppManifestAnyVersionPartial, RawComponentManifest, RawComponentManifestPartial,
};
use base64::{encode,decode};
use rand::{ rngs::OsRng, RngCore };
use std::fs::{OpenOptions};

use std::io::Write;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Key // Or `Aes128Gcm`
};

/// Given the path to a spin.toml manifest file, prepare its assets locally and
/// get a prepared application configuration consumable by a Spin execution context.
/// If a directory is provided, use it as the base directory to expand the assets,
/// otherwise create a new temporary directory.
pub async fn from_file(
    app: impl AsRef<Path>,
    base_dst: Option<impl AsRef<Path>>,
) -> Result<Application> {
    let app = absolutize(app)?;
    let mut manifest = raw_manifest_from_file(&app).await?;    
    validate_raw_app_manifest(&manifest)?;
    let result=prepare_any_version(&mut manifest, app, base_dst).await;
    result
}

/// Reads the spin.toml file as a raw manifest.
pub async fn raw_manifest_from_file(app: &impl AsRef<Path>) -> Result<RawAppManifestAnyVersion> {
    let mut buf = vec![];
    File::open(app.as_ref())
        .await
        .with_context(|| anyhow!("Cannot read manifest file from 1 {:?}", app.as_ref()))?
        .read_to_end(&mut buf)
        .await
        .with_context(|| anyhow!("Cannot read manifest file from 2 {:?}", app.as_ref()))?;
    //println!("rraw_manifest_from_file {:?} ",buf);
    let manifest: RawAppManifestAnyVersion = raw_manifest_from_slice(&buf)
        .with_context(|| anyhow!("Cannot read manifest file from 3 {:?}", app.as_ref()))?;

    Ok(manifest)
}

fn raw_manifest_from_slice(buf: &[u8]) -> Result<RawAppManifestAnyVersion> {
    let partially_parsed = toml::from_slice(buf)?;
    resolve_partials(partially_parsed)
}

/// Returns the absolute path to directory containing the file
pub fn parent_dir(file: impl AsRef<Path>) -> Result<PathBuf> {
    let path_buf = file.as_ref().parent().ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to get containing directory for file '{}'",
            file.as_ref().display()
        )
    })?;

    absolutize(path_buf)
}

/// Returns absolute path to the file
pub fn absolutize(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();

    Ok(path
        .absolutize()
        .with_context(|| format!("Failed to resolve absolute path to: {}", path.display()))?
        .to_path_buf())
}

/// Converts a raw application manifest into Spin configuration while handling
/// the Spin manifest and API version.
async fn prepare_any_version(
    raw: &mut RawAppManifestAnyVersion,
    src: impl AsRef<Path>,
    base_dst: Option<impl AsRef<Path>>,
) -> Result<Application> {
    let mut manifest = raw.clone().into_v1();
    prepare(&mut manifest, src, base_dst).await
}

/// Iterates over a vector of RawComponentManifest structs and throws an error if any component ids are duplicated
fn error_on_duplicate_ids(components: Vec<RawComponentManifest>) -> Result<()> {
    let mut ids: Vec<String> = Vec::new();
    for c in components {
        let id = c.id;
        if ids.contains(&id) {
            bail!("cannot have duplicate component IDs: {}", id);
        } else {
            ids.push(id);
        }
    }
    Ok(())
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
/// Validate fields in raw app manifest
pub fn validate_raw_app_manifest(raw: &RawAppManifestAnyVersion) -> Result<()> {
    let manifest = raw.as_v1();
    manifest
        .components
        .iter()
        .try_for_each(|c| validate_allowed_http_hosts(&c.wasm.allowed_http_hosts))?;
    manifest
        .components
        .iter()
        .try_for_each(|c| validate_key_value_stores(&c.wasm.key_value_stores))?;
    Ok(())
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
async fn prepare(
    raw: &mut RawAppManifest,
    src: impl AsRef<Path>,
    base_dst: Option<impl AsRef<Path>>,
) -> Result<Application> {

    let info = info(raw.info.clone(), &src);
    error_on_duplicate_ids(raw.components.clone())?;
    let component_info: Vec<_> = raw
        .components.clone()
        .iter()
        .map(|c| (c.id.clone(), c.app_id.clone()))
        .collect();
    use tokio::io::{BufReader,AsyncBufReadExt};

    let meta = metadata("key_moduleid").await;
    let mut app_id_unique="";
    let mut hashmap_key = HashMap::new();

    if meta.is_ok() {
        // File exists, proceed to open it
        let file = File::open("key_moduleid").await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // Asynchronously read each line
        while let Some(line) = lines.next_line().await? {
            let parts: Vec<&str> = line.split(":::").collect();
            if parts.len() == 2 {
                let key = parts[0].to_string();
                println!("encoded key in input: {}", parts[1].trim());
                if let Ok(value) = decode(parts[1].trim()) {
                    hashmap_key.insert(key, value);
                }
            }
        }
    }
    let mut file = OpenOptions::new()
        .write(true)    // Enables writing to the file
        .create(true)   // Creates the file if it doesn't exist
        .truncate(true) // Truncates the file if it already exists
        .open("key_moduleid")
        .expect("Failed to open or create file");
        

    for (id, app_id) in &component_info {
        if hashmap_key.contains_key(app_id){
            app_id_unique=app_id;
            let crypto_key_value=hashmap_key.get(app_id).unwrap();
            let encoded=encode(crypto_key_value);
            file.write_all(id.as_bytes()).expect("Failed to write to file");
            file.write_all(":::".as_bytes()).expect("Failed to write to file"); 
            file.write_all(encoded.as_bytes()).expect("Failed to write to file"); 
            file.write_all("\n".as_bytes()).expect("Failed to write to file");
        }
        else{            
            //Since in the local mode, all functions belong to an application, we
            //define only one key for all. But we write this code to generate key for
            //differnt applications.
            app_id_unique=app_id;
            let mut key: [u8; 16] = [0; 16];
            let mut rng = OsRng::new().ok().unwrap();
            rng.fill_bytes(&mut key);
            hashmap_key.insert(app_id.to_string(), key.to_vec());
            let encoded=encode(key);            
            file.write_all(id.as_bytes()).expect("Failed to write to file");
            file.write_all(":::".as_bytes()).expect("Failed to write to file"); 
            file.write_all(encoded.as_bytes()).expect("Failed to write to file"); 
            file.write_all("\n".as_bytes()).expect("Failed to write to file");
        }
    }

    let component_triggers = raw
        .components.clone()
        .iter()
        .map(|c| (c.id.clone(), c.trigger.clone()))
        .collect();

    let components = future::join_all(
        raw.components.clone()
            .into_iter()
            .map(|c| async { core(c, &src, base_dst.as_ref()).await })
            .collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()
    .context("Failed to prepare configuration")?;
    use zeroize::Zeroize;
    for (_, variable) in raw.variables.iter_mut() {
        if variable.leaklesssecret {
            // Change the default value here
            let default_tmp=variable.default.clone().expect("REASON");
            if variable.leaklessoperation.is_some() {

                let secret_type= variable.leaklessoperation.clone().expect("REASON");   
                             
                if secret_type == "sign-request" {
                    let _service = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("services").unwrap(); 
                    //write to s3_sign
                    for (id, _) in &component_info {
                        let mut file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("sign_request").unwrap(); 
                        file.write_all(id.as_bytes()).expect("Failed to write to file");
                        file.write_all(":::".as_bytes()).expect("Failed to write to file"); 
                        file.write_all(default_tmp.as_bytes()).expect("Failed to write to file"); 
                        file.write_all("\n".as_bytes()).expect("Failed to write to file");
                    }
                }
                else if secret_type == "jwt-sign" {
                    let _service = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("services").unwrap(); 
                    for (id, _) in &component_info {
                        let mut file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("jwt_sign").unwrap(); 
                        file.write_all(id.as_bytes()).expect("Failed to write to file");
                        file.write_all(":::".as_bytes()).expect("Failed to write to file"); 
                        file.write_all(default_tmp.as_bytes()).expect("Failed to write to file"); 
                        file.write_all("\n".as_bytes()).expect("Failed to write to file");
                    }
                        
                    }else if secret_type == "jwt-verify"{
                        for (id, _) in &component_info {
                            let mut file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("jwt_verify").unwrap(); 
                            file.write_all(id.as_bytes()).expect("Failed to write to file");
                            file.write_all(":::".as_bytes()).expect("Failed to write to file"); 
                            file.write_all(default_tmp.as_bytes()).expect("Failed to write to file"); 
                            file.write_all("\n".as_bytes()).expect("Failed to write to file");
                        }
                    }
            }
                    

            // }
            let app_id_unique_ref: String = app_id_unique.clone().to_string();
            let crypto_key_value=hashmap_key.get(&app_id_unique_ref).unwrap();
            let byte_slice: &mut [u8] = &mut default_tmp.as_bytes().to_owned();
            let encrypted_data = encrypt(&byte_slice, crypto_key_value).ok().unwrap();
            byte_slice.zeroize();
            let encoded_data = encode(encrypted_data);
            let prefixed_data = format!("LEAKLESS_{}_LEAKLESS", encoded_data);
            variable.default = Some(prefixed_data.to_string());
        }
    }
    let variables: HashMap<String, Variable> = raw
        .variables.clone()
        .into_iter()
        .map(|(key, var)| Ok((key, var.try_into()?)))
        .collect::<Result<_>>()?;
    raw.components = Vec::new();
    raw.variables = HashMap::new();
    raw.info.name = "".to_string();
    println!(": {}","end of the function");
    Ok(Application {
        info,
        variables,
        components,
        component_triggers,
    })
}

/// Given a raw component manifest, prepare its assets and return a fully formed core component.
async fn core(
    raw: RawComponentManifest,
    src: impl AsRef<Path>,
    base_dst: Option<impl AsRef<Path>>,
) -> Result<CoreComponent> {
    let app_id=raw.app_id;
    let id = raw.id;
    let src = parent_dir(src)?;
    let source = match raw.source {
        config::RawModuleSource::FileReference(p) => {
            let p = match p.is_absolute() {
                true => p,
                false => src.join(p),
            };

            ModuleSource::FileReference(p)
        }
        config::RawModuleSource::Url(us) => {
            let source = UrlSource::new(&us)
                .with_context(|| format!("Can't use Web source in component {}", id))?;

            let bytes = source
                .get()
                .await
                .with_context(|| format!("Can't use source {} for component {}", us.url, id))?;

            ModuleSource::Buffer(bytes, us.url)
        }
    };

    let description = raw.description;
    let mounts = match raw.wasm.files {
        Some(f) => {
            let exclude_files = raw.wasm.exclude_files.unwrap_or_default();
            assets::prepare_component(&f, src, base_dst, &id, &exclude_files).await?
        }
        None => vec![],
    };
    let environment = raw.wasm.environment.unwrap_or_default();
    let allowed_http_hosts = raw.wasm.allowed_http_hosts.unwrap_or_default();
    let key_value_stores = raw.wasm.key_value_stores.unwrap_or_default();
    let wasm = WasmConfig {
        environment,
        mounts,
        allowed_http_hosts,
        key_value_stores,
    };
    let config = raw.config.unwrap_or_default();
    Ok(CoreComponent {
        source,
        id,
        app_id,
        description,
        wasm,
        config,
    })
}

/// A parsed URL source for a component module.
#[derive(Debug)]
pub struct UrlSource {
    url: Url,
    digest: ComponentDigest,
}

impl UrlSource {
    /// Parses a URL source from a raw component manifest.
    pub fn new(us: &FileComponentUrlSource) -> anyhow::Result<UrlSource> {
        let url = reqwest::Url::parse(&us.url)
            .with_context(|| format!("Invalid source URL {}", us.url))?;
        if url.scheme() != "https" {
            anyhow::bail!("Invalid URL scheme {}: must be HTTPS", url.scheme(),);
        }

        let digest = ComponentDigest::try_from(&us.digest)?;

        Ok(Self { url, digest })
    }

    /// The URL of the source.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// A relative path URL derived from the URL.
    pub fn url_relative_path(&self) -> PathBuf {
        let path = self.url.path();
        let rel_path = path.trim_start_matches('/');
        PathBuf::from(rel_path)
    }

    /// The digest string (omitting the format).
    pub fn digest_str(&self) -> &str {
        match &self.digest {
            ComponentDigest::Sha256(s) => s,
        }
    }

    /// Gets the data from the source as a byte buffer.
    pub async fn get(&self) -> anyhow::Result<Vec<u8>> {
        // TODO: when `spin up` integrates running an app from OCI, pass the configured
        // cache root to this function. For now, use the default cache directory.
        let cache = Cache::new(None).await?;
        match cache.wasm_file(self.digest_str()) {
            Ok(p) => {
                tracing::debug!(
                    "Using local cache for module source {} with digest {}",
                    &self.url,
                    &self.digest_str()
                );
                Ok(tokio::fs::read(p).await?)
            }
            Err(_) => {
                tracing::debug!("Pulling module from URL {}", &self.url);
                let response = reqwest::get(self.url.clone())
                    .await
                    .with_context(|| format!("Error fetching source URL {}", self.url))?;
                // TODO: handle redirects
                let status = response.status();
                if status != reqwest::StatusCode::OK {
                    let reason = status.canonical_reason().unwrap_or("(no reason provided)");
                    anyhow::bail!(
                        "Error fetching source URL {}: {} {}",
                        self.url,
                        status.as_u16(),
                        reason
                    );
                }
                let body = response
                    .bytes()
                    .await
                    .with_context(|| format!("Error loading source URL {}", self.url))?;
                let bytes = body.into_iter().collect_vec();

                self.digest.verify(&bytes).context("Incorrect digest")?;
                cache.write_wasm(&bytes, self.digest_str()).await?;

                Ok(bytes)
            }
        }
    }
}

#[derive(Debug)]
enum ComponentDigest {
    Sha256(String),
}

impl TryFrom<&String> for ComponentDigest {
    type Error = anyhow::Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        if let Some((format, text)) = value.split_once(':') {
            match format {
                "sha256" => {
                    if text.is_empty() {
                        Err(anyhow!("Invalid digest string '{value}': no digest"))
                    } else {
                        Ok(Self::Sha256(text.to_owned()))
                    }
                }
                _ => Err(anyhow!(
                    "Invalid digest string '{value}': format must be sha256"
                )),
            }
        } else {
            Err(anyhow!(
                "Invalid digest string '{value}': format must be 'sha256:...'"
            ))
        }
    }
}

impl ComponentDigest {
    fn verify(&self, bytes: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Sha256(expected) => {
                let actual = &bytes_sha256_string(bytes);
                if expected == actual {
                    Ok(())
                } else {
                    Err(anyhow!("Downloaded file does not match specified digest: expected {expected}, actual {actual}"))
                }
            }
        }
    }
}

/// The parsing of a `component.trigger` table depends on the application trigger type.
/// But serde doesn't allow us to express that dependency through attributes.  In lieu
/// of writing a custom Deserialize implementation for the whole manifest, we instead
/// leave `component.trigger` initially unparsed, then once we have the rest of the
/// manifest loaded, we go back and parse it into the correct enum case - we basically
/// clone the partially-parsed manifest but changing the type of `component.trigger`
/// (which is why this can't be a straight clone).  The next few functions accomplish
/// this.
///
/// (The reason we can't continue using an untagged enum is that an external trigger
/// might have a setting called `route` which would make serde parse it as a
/// TriggerConfig::Http.  There are other ways around this, e.g. the trigger match
/// checker could see External/Http and transform the typed config back to a HashMap -
/// I went this way to avoid having to know about individual types but it has its
/// own downsides for sure.)
fn resolve_partials(
    partially_parsed: RawAppManifestAnyVersionPartial,
) -> Result<RawAppManifestAnyVersion> {
    //println!("resolve_partials");
    let manifest = partially_parsed.into_v1();

    let app_trigger = &manifest.info.trigger;
    let components = manifest
        .components
        .into_iter()
        .map(|c| resolve_partial_component(app_trigger, c))
        .collect::<Result<_>>()?;

    // Only concerned with preserving manifest.
    Ok(RawAppManifestAnyVersion::V1New {
        manifest: RawAppManifest {
            info: manifest.info,
            components,
            variables: manifest.variables,
        },
        spin_manifest_version: config::FixedStringVersion::default(),
    })
}

fn resolve_partial_component(
    app_trigger: &ApplicationTrigger,
    partial: RawComponentManifestPartial,
) -> Result<RawComponentManifest> {
    let trigger = resolve_trigger(app_trigger, partial.trigger)?;

    Ok(RawComponentManifest {
        id: partial.id,
        app_id: partial.app_id,
        source: partial.source,
        description: partial.description,
        wasm: partial.wasm,
        trigger,
        build: partial.build,
        config: partial.config,
    })
}

fn resolve_trigger(
    app_trigger: &ApplicationTrigger,
    partial: toml::Value,
) -> Result<TriggerConfig> {
    use serde::Deserialize;
    let tc = match app_trigger {
        ApplicationTrigger::Http(_) => TriggerConfig::Http(HttpConfig::deserialize(partial)?),
        ApplicationTrigger::Redis(_) => TriggerConfig::Redis(RedisConfig::deserialize(partial)?),
        ApplicationTrigger::External(_) => TriggerConfig::External(HashMap::deserialize(partial)?),
    };
    Ok(tc)
}

/// Converts the raw application information from the spin.toml manifest to the standard configuration.
fn info(raw: RawAppInformation, src: impl AsRef<Path>) -> ApplicationInformation {
    ApplicationInformation {
        spin_version: SpinVersion::V1,
        name: raw.name,
        version: raw.version,
        description: raw.description,
        authors: raw.authors.unwrap_or_default(),
        trigger: raw.trigger,
        origin: ApplicationOrigin::File(src.as_ref().to_path_buf()),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn load_test_manifest(app_trigger: &str, comp_trigger: &str) -> RawAppManifestAnyVersion {
        let manifest_toml = format!(
            r#"
spin_version = "1"
name = "test"
trigger = {app_trigger}
version = "0.0.1"

[[component]]
id = "test"
source = "nonexistent.wasm"
[component.trigger]
{comp_trigger}
"#
        );

        let manifest = raw_manifest_from_slice(manifest_toml.as_bytes()).unwrap();
        validate_raw_app_manifest(&manifest).unwrap();

        manifest
    }

    #[test]
    fn can_parse_http_trigger() {
        let m = load_test_manifest(r#"{ type = "http", base = "/" }"#, r#"route = "/...""#);
        let m1 = m.into_v1();
        let t = &m1.info.trigger;
        let ct = &m1.components[0].trigger;
        assert!(matches!(t, ApplicationTrigger::Http(_)));
        assert!(matches!(ct, TriggerConfig::Http(_)));
    }

    #[test]
    fn can_parse_redis_trigger() {
        let m = load_test_manifest(
            r#"{ type = "redis", address = "dummy" }"#,
            r#"channel = "chan""#,
        );

        let m1 = m.into_v1();
        let t = m1.info.trigger;
        let ct = &m1.components[0].trigger;
        assert!(matches!(t, ApplicationTrigger::Redis(_)));
        assert!(matches!(ct, TriggerConfig::Redis(_)));
    }

    #[test]
    fn can_parse_unknown_trigger() {
        let m = load_test_manifest(r#"{ type = "pounce" }"#, r#"on = "MY KNEES""#);

        let m1 = m.into_v1();
        let t = m1.info.trigger;
        let ct = &m1.components[0].trigger;
        assert!(matches!(t, ApplicationTrigger::External(_)));
        assert!(matches!(ct, TriggerConfig::External(_)));
    }

    #[test]
    fn external_triggers_can_have_same_config_keys_as_builtins() {
        let m = load_test_manifest(
            r#"{ type = "pounce" }"#,
            r#"route = "over the cat tree and out of the sun""#,
        );

        let m1 = m.into_v1();
        let t = m1.info.trigger;
        let ct = &m1.components[0].trigger;
        assert!(matches!(t, ApplicationTrigger::External(_)));
        assert!(matches!(ct, TriggerConfig::External(_)));
    }
}