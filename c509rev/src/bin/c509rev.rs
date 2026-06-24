//! `c509rev` CLI — encode/decode/sign/verify C509 CRL and OCSP messages.
//!
//! Stub: the subcommands are filled in as the crl/ocsp modules land
//! (see REFERENCE-IMPL-PLAN.md). For now it reports usage and the supported
//! object types so the binary target builds and is wired into the crate.

fn main() {
    eprintln!("c509rev — C509 Certificate Revocation Management reference tool");
    eprintln!();
    eprintln!("usage: c509rev <object> <action> <files...>");
    eprintln!("  object: crl | ocsp-req | ocsp-resp");
    eprintln!("  action: encode | decode | sign | verify");
    eprintln!();
    eprintln!("(subcommands not yet implemented — scaffold only)");
    std::process::exit(2);
}
