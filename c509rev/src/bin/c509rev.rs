//! `c509rev` CLI — decode, verify, and PEM-wrap C509 CRL / OCSP messages.
//!
//! Usage:
//!   c509rev <object> decode <infile>
//!   c509rev <object> verify <infile> <pubkey-hex>
//!   c509rev <object> pem    <infile>
//!     object: crl | ocsp-req | ocsp-resp
//!
//! <infile> holds the object's CBOR as either hex (whitespace ignored) or a
//! PEM textual representation (`-----BEGIN C509 ...-----`); the format is
//! auto-detected. `verify` checks the signature over the TBS against the given
//! public key (Ed25519 32-byte, or secp256r1 SEC1). `pem` re-emits the object
//! as its PEM textual representation. Encoding from a source format is not yet
//! wired.
//!
//! Reference tooling only. Not for production use.

use std::process::exit;

use c509rev::crl::C509Crl;
use c509rev::ocsp_req::C509OcspRequest;
use c509rev::ocsp_resp::C509OcspResponse;
use c509rev::pem;

/// The PEM label for an object keyword.
fn pem_label(object: &str) -> &'static str {
    match object {
        "crl" => pem::LABEL_CRL,
        "ocsp-req" => pem::LABEL_OCSP_REQUEST,
        "ocsp-resp" => pem::LABEL_OCSP_RESPONSE,
        other => {
            eprintln!("unknown object '{other}' (crl|ocsp-req|ocsp-resp)");
            exit(2);
        }
    }
}

/// Read the object's CBOR bytes from `path`, auto-detecting PEM vs hex. When the
/// input is PEM, its label must match `label`.
fn read_input(path: &str, label: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        exit(2);
    });
    if text.contains("-----BEGIN ") {
        return pem::decode_expecting(label, &text).unwrap_or_else(|e| {
            eprintln!("{path} is not a valid {label} PEM: {e}");
            exit(2);
        });
    }
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&cleaned).unwrap_or_else(|e| {
        eprintln!("{path} is not valid hex: {e}");
        exit(2);
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: {} <crl|ocsp-req|ocsp-resp> <decode|verify|pem> <infile> [pubkey-hex]",
                  args.first().map(String::as_str).unwrap_or("c509rev"));
        exit(2);
    }
    let object = args[1].as_str();
    let action = args[2].as_str();
    let label = pem_label(object);
    let bytes = read_input(&args[3], label);

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
        "pem" => {
            // Re-emit the (validated) object as its PEM textual representation.
            print!("{}", pem::encode(label, &bytes));
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
            eprintln!("unknown action '{other}' (decode|verify|pem)");
            exit(2);
        }
    }
}

fn fail_decode<T, E: std::fmt::Display>(e: E) -> T {
    eprintln!("decode failed: {e}");
    exit(1);
}
