//! Crypto / encoding builtin functions for the feed engine.
//!
//! Registered into the Rhai engine alongside the string builtins so feeds can
//! compute digests, HMACs and base64 inside `script` steps and `condition:`
//! expressions (e.g. verify a signed token, derive an expected hash, decode a
//! base64 blob from a response). All take/return strings; digests return lowercase
//! hex. Backed by the RustCrypto crates.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rhai::Engine;
use sha2::{Digest, Sha256};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest_hex<D: Digest>(data: &str) -> String {
    let mut h = D::new();
    h.update(data.as_bytes());
    to_hex(&h.finalize())
}

fn hmac_sha256_hex(key: &str, msg: &str) -> String {
    // new_from_slice accepts any key length for HMAC, so this cannot fail here.
    match Hmac::<Sha256>::new_from_slice(key.as_bytes()) {
        Ok(mut mac) => {
            mac.update(msg.as_bytes());
            to_hex(&mac.finalize().into_bytes())
        }
        Err(_) => String::new(),
    }
}

/// Register the crypto/encoding builtins onto `engine`.
pub fn register(engine: &mut Engine) {
    engine.register_fn("md5", |s: &str| digest_hex::<md5::Md5>(s));
    engine.register_fn("sha1", |s: &str| digest_hex::<sha1::Sha1>(s));
    engine.register_fn("sha256", |s: &str| digest_hex::<Sha256>(s));
    engine.register_fn("sha512", |s: &str| digest_hex::<sha2::Sha512>(s));
    engine.register_fn("hmac_sha256", hmac_sha256_hex);

    engine.register_fn("base64_encode", |s: &str| STANDARD.encode(s.as_bytes()));
    // Lossy: invalid base64 or non-UTF8 output yields "" (feeds test the result).
    engine.register_fn("base64_decode", |s: &str| {
        STANDARD
            .decode(s.as_bytes())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Engine;

    fn eng() -> Engine {
        let mut e = Engine::new();
        register(&mut e);
        e
    }

    fn eval_str(code: &str) -> String {
        eng().eval::<String>(code).expect("eval ok")
    }

    #[test]
    fn digests_match_known_vectors() {
        assert_eq!(eval_str(r#"md5("")"#), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            eval_str(r#"sha1("abc")"#),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            eval_str(r#"sha256("abc")"#),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            eval_str(r#"sha512("abc")"#),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231-style: key "key", data "The quick brown fox jumps over the lazy dog"
        assert_eq!(
            eval_str(r#"hmac_sha256("key", "The quick brown fox jumps over the lazy dog")"#),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn base64_roundtrip() {
        assert_eq!(eval_str(r#"base64_encode("hello")"#), "aGVsbG8=");
        assert_eq!(eval_str(r#"base64_decode("aGVsbG8=")"#), "hello");
        assert_eq!(eval_str(r#"base64_decode("!!not base64!!")"#), ""); // invalid → ""
    }
}
