//! Binary pack/unpack and random-token builtins for the feed engine.
//!
//! `pack` helpers (`p8`/`p16be`/`p16le`/`p32be`/`p32le`/`p64be`/`p64le`) render a
//! fixed-width integer as a lowercase hex string, for composing `send_hex`
//! frames (e.g. a length prefix for a binary protocol). `unpack` helpers
//! (`u8`/`u16be`/`u16le`/`u32be`/`u32le`/`u64be`/`u64le`) read a fixed-width
//! integer back out of a hex string. `rand_int`/`rand_str`/`rand_hex` produce
//! non-cryptographic random markers for probes that need a unique token.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rhai::Engine;

/// xorshift64* PRNG state, seeded lazily from the clock. Non-cryptographic —
/// used only to produce unique probe markers, never for security decisions.
static STATE: AtomicU64 = AtomicU64::new(0);
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_rand() -> u64 {
    let mut x = STATE.load(Ordering::Relaxed);
    if x == 0 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e3779b97f4a7c15);
        x = nanos ^ 0x9e3779b97f4a7c15;
        if x == 0 {
            x = 0x9e3779b97f4a7c15;
        }
    }
    // Mix in a per-call counter so concurrent callers don't correlate.
    x ^= COUNTER.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    STATE.store(x | 1, Ordering::Relaxed);
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string (whitespace/`:` ignored) into bytes; empty on bad input.
fn decode_hex(s: &str) -> Vec<u8> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match u8::from_str_radix(&cleaned[i..i + 2], 16) {
            Ok(b) => out.push(b),
            Err(_) => return Vec::new(),
        }
        i += 2;
    }
    out
}

/// Read the first `n` bytes of `hex` as a big/little-endian unsigned integer.
fn unpack(hex: &str, n: usize, big_endian: bool) -> i64 {
    let bytes = decode_hex(hex);
    if bytes.len() < n {
        return 0;
    }
    let mut acc: u64 = 0;
    if big_endian {
        for &b in &bytes[..n] {
            acc = (acc << 8) | b as u64;
        }
    } else {
        for i in (0..n).rev() {
            acc = (acc << 8) | bytes[i] as u64;
        }
    }
    acc as i64
}

/// Register the pack/unpack and random builtins onto `engine`.
pub fn register(engine: &mut Engine) {
    // ── pack: integer → hex ────────────────────────────────────────────────
    engine.register_fn("p8", |n: i64| to_hex(&[(n as u8)]));
    engine.register_fn("p16be", |n: i64| to_hex(&(n as u16).to_be_bytes()));
    engine.register_fn("p16le", |n: i64| to_hex(&(n as u16).to_le_bytes()));
    engine.register_fn("p32be", |n: i64| to_hex(&(n as u32).to_be_bytes()));
    engine.register_fn("p32le", |n: i64| to_hex(&(n as u32).to_le_bytes()));
    engine.register_fn("p64be", |n: i64| to_hex(&(n as u64).to_be_bytes()));
    engine.register_fn("p64le", |n: i64| to_hex(&(n as u64).to_le_bytes()));

    // ── unpack: hex → integer ──────────────────────────────────────────────
    engine.register_fn("u8", |h: &str| unpack(h, 1, true));
    engine.register_fn("u16be", |h: &str| unpack(h, 2, true));
    engine.register_fn("u16le", |h: &str| unpack(h, 2, false));
    engine.register_fn("u32be", |h: &str| unpack(h, 4, true));
    engine.register_fn("u32le", |h: &str| unpack(h, 4, false));
    engine.register_fn("u64be", |h: &str| unpack(h, 8, true));
    engine.register_fn("u64le", |h: &str| unpack(h, 8, false));

    // ── rand: non-crypto markers ───────────────────────────────────────────
    engine.register_fn("rand_int", |min: i64, max: i64| {
        if max <= min {
            return min;
        }
        let span = (max - min + 1) as u64;
        min + (next_rand() % span) as i64
    });
    engine.register_fn("rand_str", |n: i64| {
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let n = n.clamp(0, 4096) as usize;
        (0..n)
            .map(|_| ALPHA[(next_rand() % ALPHA.len() as u64) as usize] as char)
            .collect::<String>()
    });
    engine.register_fn("rand_hex", |n: i64| {
        let n = n.clamp(0, 4096) as usize;
        let bytes: Vec<u8> = (0..n).map(|_| next_rand() as u8).collect();
        to_hex(&bytes)
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

    #[test]
    fn pack_big_and_little_endian() {
        let e = eng();
        assert_eq!(e.eval::<String>("p8(255)").unwrap(), "ff");
        assert_eq!(e.eval::<String>("p16be(258)").unwrap(), "0102");
        assert_eq!(e.eval::<String>("p16le(258)").unwrap(), "0201");
        assert_eq!(e.eval::<String>("p32be(1)").unwrap(), "00000001");
        assert_eq!(e.eval::<String>("p32le(1)").unwrap(), "01000000");
        assert_eq!(e.eval::<String>("p64be(1)").unwrap(), "0000000000000001");
    }

    #[test]
    fn unpack_reads_prefix() {
        let e = eng();
        assert_eq!(e.eval::<i64>(r#"u8("ff00")"#).unwrap(), 255);
        assert_eq!(e.eval::<i64>(r#"u16be("0102")"#).unwrap(), 258);
        assert_eq!(e.eval::<i64>(r#"u16le("0201")"#).unwrap(), 258);
        assert_eq!(e.eval::<i64>(r#"u32be("0000002a")"#).unwrap(), 42);
        assert_eq!(e.eval::<i64>(r#"u32le("2a000000")"#).unwrap(), 42);
        // not enough bytes → 0
        assert_eq!(e.eval::<i64>(r#"u32be("00")"#).unwrap(), 0);
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let e = eng();
        assert_eq!(e.eval::<i64>("u32be(p32be(123456))").unwrap(), 123456);
        assert_eq!(e.eval::<i64>("u32le(p32le(987654))").unwrap(), 987654);
        assert_eq!(e.eval::<i64>("u16be(p16be(4096))").unwrap(), 4096);
    }

    #[test]
    fn rand_shapes_and_bounds() {
        let e = eng();
        assert_eq!(e.eval::<String>("rand_str(10)").unwrap().len(), 10);
        assert_eq!(e.eval::<String>("rand_hex(4)").unwrap().len(), 8);
        assert_eq!(e.eval::<i64>("rand_int(5, 5)").unwrap(), 5);
        for _ in 0..100 {
            let v = e.eval::<i64>("rand_int(10, 20)").unwrap();
            assert!((10..=20).contains(&v), "out of range: {v}");
        }
        // tokens are hex / alphanumeric
        assert!(e
            .eval::<String>("rand_hex(8)")
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }
}
