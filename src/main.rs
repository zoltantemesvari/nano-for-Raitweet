#![forbid(unsafe_code)]
#![cfg_attr(feature = "deny_warnings", deny(warnings))]

use crate::keys::{address::Address, signature::Signature, public::Public};


mod keys;
mod encoding;
mod errors;


fn main() {
    
    let message = "secret message!".as_bytes();

    let signature_received = "17523D9479E0F8CABE72D9F6066B298B712774040BDC2C6AC9D926BAEDC8AC65145BCBBE9A4B1731F36B063636329BEA9DA680026FED58F2AEFB9FE61D4D9B03";
    let address_received = "nano_3phqgrqbso99xojkb1bijmfryo7dy1k38ep1o3k3yrhb7rqu1h1k47yu78gz";

    let address: Address = address_received.parse::<keys::address::Address>().unwrap();
    let signature: Signature = signature_received.parse::<keys::signature::Signature>().unwrap();

    println!("address: {}",address.to_string());
    println!("signature: {:?}",signature);

    // Someone else can verify the message based on your address or public key.
    //address.to_public().verify(message, &signature).unwrap();
    let public_key = address.to_public();
    println!("{:?}",public_key);
    public_key.verify(message, &signature).unwrap();
}
