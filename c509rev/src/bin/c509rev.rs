//! `c509rev` CLI — decode and verify C509 CRL / OCSP messages.
//!
//! Usage:
//!   c509rev <object> decode <hexfile>
//!   c509rev <object> verify <hexfile> <pubkey-hex>
//!     object: crl | ocsp-req | ocsp-resp
//!
//! <hexfile> contains the object's CBOR as hex (whitespace ignored). `verify`
//! checks the signature over the TBS against the given public key (Ed25519
//! 32-byte, or secp256r1 SEC1). Encoding from a source format is not yet wired.
//!
//! Reference tooling only. Not for production use.

use std::process::exit;

use c509rev::crl::C509Crl;
use c509rev::ocsp_req::C509OcspRequest;
use c509rev::ocsp_resp::C509OcspResponse;

fn read_hex(path: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        exit(2);
    });
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&cleaned).unwrap_or_else(|e| {
        eprintln!("{path} is not valid hex: {e}");
        exit(2);
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: {} <crl|ocsp-req|ocsp-resp> <decode|verify> <hexfile> [pubkey-hex]",
                  args.first().map(String::as_str).unwrap_or("c509rev"));
        exit(2);
    }
    let object = args[1].as_str();
    let action = args[2].as_str();
    let bytes = read_hex(&args[3]);

    // Decode into a Debug string + an optional verify closure over a pubkey.
    type Verifier = Box<dyn Fn(&[u8]) -> Result<(), c509rev::sign::VerifyError>>;
    let (debug, verifier): (String, Verifier) = match object {
        "crl" => {
            let o = C509Crl::decode(&bytes).unwrap_or_else(fail_decode);
            (format!("{o:#?}"), Box::new(move |pk| o.verify(pk)))
        }
        "ocsp-req" => {
            let o = C509OcspRequest::decode(&bytes).unwrap_or_else(fail_decode);
            (format!("{o:#?}"), Box::new(move |pk| o.verify(pk)))
        }
        "ocsp-resp" => {
            let o = C509OcspResponse::decode(&bytes).unwrap_or_else(fail_decode);
            (format!("{o:#?}"), Box::new(move |pk| o.verify(pk)))
        }
        other => {
            eprintln!("unknown object '{other}' (crl|ocsp-req|ocsp-resp)");
            exit(2);
        }
    };

    match action {
        "decode" => {
            println!("{debug}");
        }
        "verify" => {
            if args.len() < 5 {
                eprintln!("verify needs <pubkey-hex>");
                exit(2);
            }
            let pk = hex::decode(args[4].trim()).unwrap_or_else(|e| {
                eprintln!("bad pubkey hex: {e}");
                exit(2);
            });
            match verifier(&pk) {
                Ok(()) => println!("VERIFY OK"),
                Err(e) => {
                    eprintln!("VERIFY FAILED: {e:?}");
                    exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown action '{other}' (decode|verify)");
            exit(2);
        }
    }
}

fn fail_decode<T, E: std::fmt::Display>(e: E) -> T {
    eprintln!("decode failed: {e}");
    exit(1);
}
