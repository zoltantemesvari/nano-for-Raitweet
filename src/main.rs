#![forbid(unsafe_code)]
#![cfg_attr(feature = "deny_warnings", deny(warnings))]
#![cfg_attr(feature = "deny_warnings", deny(clippy::all))]

use crate::keys::{address::Address, signature::Signature};
use keys::public::validate_message;
use reqwest;

mod keys;
mod encoding;
mod errors;


#[tokio::main]
async fn main() {

    #[derive(serde::Deserialize, Debug)]
    struct NanosCCResponse {
        requestLimitReset: String,
        requestsLimit: String,
        account: String,
        requestsRemaining: String
    }

    const NANOSCC_ENDPOINT: &str = "https://proxy.nanos.cc/proxy/?action=block_account&hash=";
    
    let block_hash = "message";
    let message = block_hash.as_bytes();

    let signature_received = "e6752b7c86fd04f87cb3989458d688110fa4e972d8cc5bf9b31942380fc076464873770e27c962d39581c61dca9b38498cb857391341b895b6387b4b561c8304";
    let address_received = "nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d";

    let address: Address = address_received.parse::<keys::address::Address>().unwrap();
    let signature: Signature = signature_received.parse::<keys::signature::Signature>().unwrap();

    println!("address: {}",address.to_string());
    println!("signature: {:?}",signature);

    // Someone else can verify the message based on your address or public key.
    //address.to_public().verify(message, &signature).unwrap();
    let public_key = address.to_public();
    println!("{:?}",public_key);

    match public_key.verify(message, &signature) {
        Ok(_) => println!("Signature is valid"),
        Err(errrormessage) => println!("Invalid signature: {:?}", errrormessage),
    }

    match validate_message(&public_key, message, &signature) 

{
        Ok(_) => println!("Signature is valid"),
        Err(errrormessage) => println!("Invalid signature: {:?}", errrormessage),
    }

    // Someone else can verify the message based on your address or public key.
    //address.to_public().verify(message, &signature).unwrap();
    //let public_key = address.to_public();
    //println!("{:?}",public_key);

    //match public_key.verify(message, &signature) {
    //    Ok(_) => println!("Signature is valid"),
    //    Err(errrormessage) => println!("Invalid signature: {:?}", errrormessage),
    //}

    //match validate_message(public_key, message, signature)
async fn block_account(block_hash: &str) -> Result<String, Box<dyn std::error::Error>> {
    let endpoint = String::from(NANOSCC_ENDPOINT);
    let full_endpoint = endpoint + block_hash;
    let resp = reqwest::get(&full_endpoint)
        .await?
        .json::<NanosCCResponse>()
        .await?;
    println!("{:#?}", resp);
    Ok(resp.account)
}

// match block_account(block_hash).await {
//    Ok(account) => println!("Account: {}", account),
//    Err(e) => println!("Error: {}", e),
//
//};

}
