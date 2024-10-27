extern crate proc_macro;
use proc_macro::TokenStream;
use proc_macro::TokenTree;
use quote::{format_ident, quote};
//use proc_macro2::Literal;
use base64::{encode};
use std::fs;
//use std::io::BufReader;
use rand::{ rngs::OsRng, RngCore };
use std::fs::{File, OpenOptions};
use std::io::Write;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use std::io::{BufRead, BufReader};
//use std::io::BufRead;
use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Key // Or `Aes128Gcm`
};
use std::collections::HashMap;
use base64::decode;

fn read_keys_from_file() -> HashMap<String, Vec<u8>> {
    let mut hashmap_keys = HashMap::new();
    if let Ok(metadata) = fs::metadata("key_moduleid") {
        if metadata.is_file() {
            let file = File::open("key_moduleid").expect("Failed to open file");
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line.expect("Failed to read line");
                let parts: Vec<&str> = line.split(":::").collect();
                if parts.len() == 2 {
                    let key = parts[0].to_string();
                    let value = decode(parts[1].trim()).expect("Failed to decode binary data");
                    hashmap_keys.insert(key, value);
                } else {
                    println!("Skipping invalid line: {}", line);
                }
            }
        }
    }
    hashmap_keys
}

fn parse_component_ids() -> HashMap<String, String> {
    let file = File::open("spin.toml").unwrap();
    let reader = BufReader::new(file);
    let component_regex = regex::Regex::new(r#"^\s*id\s*=\s*"([^"]+)""#).unwrap();
    let mut component_ids = HashMap::new();
    let mut current_id = String::new();
    let mut in_component_section = false;

    for line in reader.lines() {
        let line = line.unwrap();
        if let Some(captures) = component_regex.captures(&line) {
            current_id = captures.get(1).unwrap().as_str().to_string();
            in_component_section = true;
        } else if in_component_section && line.starts_with("app_id =") {
            let _current_id = line.splitn(2, "app_id = ").nth(1).unwrap().trim_matches('"').to_string();
            component_ids.insert(current_id.clone(), _current_id.clone());
            in_component_section = false;
        }
    }
    component_ids
}

#[proc_macro_attribute]
pub fn leakless_secret(_tokens: TokenStream, input: TokenStream) -> TokenStream {
    let hashmap_keys = read_keys_from_file();
    let component_ids = parse_component_ids();
    let input: Vec<TokenTree> = input.into_iter().collect();
    if let Some(TokenTree::Ident(ident)) = input.first() {
        match ident.to_string().as_str() {
            "const" =>{                
                let mut i=input.len();
                let mut value="".to_string();
                let name=   match &input.get(1) {
                    Some(TokenTree::Ident(ident)) => ident.to_string(),
                    _ => "".to_string()
                };
                while i > 0 as usize{        
                    value = match &input.get(i) {
                        Some(TokenTree::Literal(literal)) =>{
                            literal.to_string()},
                        _ => "".to_string()
                    };
                    if value !=""{
                        break;
                    }
                    i=i-1;
                }       
                  
                let mut chars = value.chars();
                chars.next();
                chars.next_back();
                let char_vec: Vec<char> = chars.collect();
            
              
                let file_path = "signal"; 
                if fs::metadata(file_path).is_ok() {
                    let file_contents = fs::read_to_string("signal").expect("Failed to read file.");
                    let id = file_contents.trim().to_string();
                    fs::remove_file("signal").expect("Failed to remove file.");
                    if let Some(app_id) = component_ids.get(&id) {
                        if let Some((_, crypto_key_value)) = hashmap_keys.iter().find(|(other_id, _)| {
                            component_ids.get(*other_id).map_or(false, |other_app_id| other_app_id == app_id)
                        }) {
                            let char_string: String = char_vec.iter().collect();
                            //println!("char_string 1 {:?}", char_string);
                            let byte_slice: &[u8] = char_string.as_bytes();                            
                            let encrypted_data = encrypt(&byte_slice, crypto_key_value).ok().unwrap();
                            let encoded_data = encode(encrypted_data);
                            let prefixed_data = format!("LEAKLESS_{}_LEAKLESS", encoded_data);
                            let var_name = format_ident!("{}",name);
                    
                            let quoted = quote! {
                                const #var_name: &str = #prefixed_data;
                            };
                            println!("{}", quoted); 
                            quoted.into()
                        }
                        else{
                            let mut file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("key_moduleid").unwrap(); 
                
                            let mut crypto_key_value: [u8; 16] = [0; 16];
                            let mut rng = OsRng::new().ok().unwrap();
                            rng.fill_bytes(&mut crypto_key_value);
                            println!("crypto_key_value in compiler {:?}", crypto_key_value);
                            let encoded=encode(crypto_key_value); 
                            //println!("encoded {:?}", encoded);           
                            file.write_all(id.as_bytes()).expect("Failed to write to file");
                            file.write_all(":::".as_bytes()).expect("Failed to write to file"); 
                            file.write_all(encoded.as_bytes()).expect("Failed to write to file"); 
                            file.write_all("\n".as_bytes()).expect("Failed to write to file");
                            let char_string: String = char_vec.iter().collect();
                            //println!("char_string {:?}", char_string); 
                            let byte_slice: &[u8] = char_string.as_bytes();
                            let encrypted_data = encrypt(&byte_slice, &crypto_key_value).ok().unwrap();
                            let encoded_data = encode(encrypted_data);
                            let prefixed_data = format!("LEAKLESS_{}_LEAKLESS", encoded_data);
                            let var_name = format_ident!("{}",name);
                            
                            let quoted = quote! {
                                const #var_name: &str = #prefixed_data;
                            };
                            println!("{}", quoted);
                            quoted.into()
                        }
                    }
                    else{
                        println!("{}", "You must add '--source-code' in the build command in Spin.toml."); 
                        return TokenStream::from(quote! {
                        });
                    }
            
                }
                else{
                    println!("{}", "You must add '--source-code' in the build command in Spin.toml.)");
                    return TokenStream::from(quote! {
                    });
                }

            },
            _ => {
                println!("{}", " Type does not support! Please define your LeakLess supported secret as a const"); 
                return TokenStream::from(quote! {
                });
            },
        }
    } else {
        println!("First token is not an identifier");
        return TokenStream::from(quote! {
        });
    }
    
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