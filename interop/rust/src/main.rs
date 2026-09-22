//! Cross-check CLI around Cloudflare's Rust crate `web-bot-auth` 0.7.0.
//!   kya-interop sign   <url> <signature-agent-url>      -> JSON headers on stdout
//!   kya-interop verify <method> <url> <headers-json>    -> RUST_VERIFY_OK | RUST_VERIFY_FAIL <why>
//! Uses the RFC 9421 Appendix B.1.4 Ed25519 test key (public test material).
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use indexmap::IndexMap;
use sfv::SerializeValue;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use web_bot_auth::WebBotAuthVerifier;
use web_bot_auth::components::{CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParameters, HTTPFieldParametersSet};
use web_bot_auth::keyring::{Algorithm, KeyRing};
use web_bot_auth::message_signatures::{MessageSigner, SignedMessage, UnsignedMessage};

const D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
const KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

fn split_url(url: &str) -> (String, String) {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let (auth, path) = match rest.find('/') { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "/") };
    let path = path.split('?').next().unwrap_or("/");
    (auth.to_lowercase(), path.to_string())
}

struct Unsigned { authority: String, agent: String, input: String, sig: String }

impl UnsignedMessage for Unsigned {
    fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String> {
        IndexMap::from_iter([
            (CoveredComponent::Derived(DerivedComponent::Authority { req: false }), self.authority.clone()),
            (CoveredComponent::HTTP(HTTPField { name: "signature-agent".into(),
                parameters: HTTPFieldParametersSet(vec![HTTPFieldParameters::Key("agent1".into())]) }),
             format!("\"{}\"", self.agent)),
        ])
    }
    fn register_header_contents(&mut self, signature_input: String, signature_header: String) {
        self.input = format!("sig1={signature_input}");
        self.sig = format!("sig1={signature_header}");
    }
}

struct Signed { method: String, authority: String, path: String, headers: HashMap<String, String> }

impl SignedMessage for Signed {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        match name {
            CoveredComponent::Derived(DerivedComponent::Authority { .. }) => vec![self.authority.clone()],
            CoveredComponent::Derived(DerivedComponent::Method { .. }) => vec![self.method.to_uppercase()],
            CoveredComponent::Derived(DerivedComponent::Path { .. }) => vec![self.path.clone()],
            CoveredComponent::HTTP(HTTPField { name, parameters }) => {
                let Some(raw) = self.headers.get(name) else { return vec![] };
                for p in &parameters.0 {
                    if let HTTPFieldParameters::Key(k) = p {
                        let Ok(dict) = sfv::Parser::new(raw).parse_dictionary() else { return vec![] };
                        return match dict.get(k.as_str()) {
                            Some(sfv::ListEntry::Item(item)) => vec![item.serialize_value()],
                            _ => vec![],
                        };
                    }
                }
                vec![raw.trim().to_string()]
            }
            _ => vec![],
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("sign") => {
            let (authority, _) = split_url(&args[2]);
            let mut msg = Unsigned { authority, agent: args[3].clone(), input: String::new(), sig: String::new() };
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let signer = MessageSigner { keyid: KEYID.into(), nonce: URL_SAFE_NO_PAD.encode(nanos.to_be_bytes()),
                                         tag: "web-bot-auth".into() };
            let sk = URL_SAFE_NO_PAD.decode(D).unwrap();
            signer.generate_signature_headers_content(&mut msg, Duration::from_secs(60), Algorithm::Ed25519, sk.as_slice())
                .expect("sign");
            println!("{}", serde_json::json!({"Signature-Agent": format!("agent1=\"{}\"", args[3]),
                                             "Signature-Input": msg.input, "Signature": msg.sig}));
        }
        Some("verify") => {
            let (authority, path) = split_url(&args[3]);
            let raw: HashMap<String, String> = serde_json::from_str(&args[4]).expect("headers json");
            let headers = raw.into_iter().map(|(k, v)| (k.to_lowercase(), v)).collect();
            let msg = Signed { method: args[2].clone(), authority, path, headers };
            let mut ring = KeyRing::default();
            ring.import_raw(KEYID.into(), Algorithm::Ed25519, URL_SAFE_NO_PAD.decode(X).unwrap());
            match WebBotAuthVerifier::parse(&msg).and_then(|v| v.verify(&ring, None)) {
                Ok(_) => println!("RUST_VERIFY_OK"),
                Err(e) => println!("RUST_VERIFY_FAIL {e:?}"),
            }
        }
        _ => { eprintln!("usage: kya-interop sign <url> <agent> | verify <method> <url> <headers-json>"); std::process::exit(2) }
    }
}
