use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate a random hex string of `byte_count` random bytes (output = 2*byte_count hex chars).
pub fn random_hex(byte_count: usize) -> String {
    let mut buf = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Build an HMAC-SHA256 binding token from the server secret + contextual data.
/// This binds a challenge to a specific client context (IP, User-Agent, etc).
pub fn compute_binding(server_secret: &[u8], ip: &str, user_agent: &str, session_nonce: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret)
        .expect("HMAC accepts any key length");
    mac.update(ip.as_bytes());
    mac.update(b"|");
    mac.update(user_agent.as_bytes());
    mac.update(b"|");
    mac.update(session_nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build the challenge prefix for a single round.
///
/// Format: `{binding}:{round_salt}:{round_index}:`
///
/// This is designed to be >55 bytes so that `prefix + nonce` exceeds 64 bytes,
/// forcing SHA-256 into double-block mode (defeats single-block hotstarting).
pub fn build_round_prefix(binding: &str, round_salt: &str, round_index: u32) -> String {
    format!("{binding}:{round_salt}:{round_index}:")
}

/// Build the hashable message for a round: `prefix + nonce_hex`.
pub fn build_message(prefix: &str, nonce_hex: &str) -> String {
    format!("{prefix}{nonce_hex}")
}

/// SHA-256 hash, returned as hex string.
pub fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

/// Count leading zero bits in a hex string.
pub fn leading_zero_bits_hex(hex_str: &str) -> u32 {
    let mut bits = 0u32;
    for ch in hex_str.bytes() {
        let nibble = match ch {
            b'0' => 0u8,
            b'1' => 1,
            b'2' => 2,
            b'3' => 3,
            b'4' => 4,
            b'5' => 5,
            b'6' => 6,
            b'7' => 7,
            b'8' => 8,
            b'9' => 9,
            b'a' | b'A' => 10,
            b'b' | b'B' => 11,
            b'c' | b'C' => 12,
            b'd' | b'D' => 13,
            b'e' | b'E' => 14,
            b'f' | b'F' => 15,
            _ => return bits,
        };
        if nibble == 0 {
            bits += 4;
        } else {
            bits += nibble.leading_zeros() - 4;
            break;
        }
    }
    bits
}

/// Verify that `SHA-256(prefix + nonce_hex)` has at least `difficulty` leading zero bits,
/// and that `nonce_hex` is valid lowercase hex (prevents integer nonce tricks).
pub fn verify_round(prefix: &str, nonce_hex: &str, difficulty: u32) -> bool {
    // Enforce hex-only nonce (no integer manipulation tricks)
    if nonce_hex.is_empty() || nonce_hex.len() > 64 {
        return false;
    }
    if !nonce_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let msg = build_message(prefix, nonce_hex);
    let hash = sha256_hex(&msg);
    leading_zero_bits_hex(&hash) >= difficulty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits_hex("0000f"), 16);
        assert_eq!(leading_zero_bits_hex("00001"), 19);
        assert_eq!(leading_zero_bits_hex("0001"), 15);
        assert_eq!(leading_zero_bits_hex("0010"), 11);
        assert_eq!(leading_zero_bits_hex("1000"), 3);
        assert_eq!(leading_zero_bits_hex("8000"), 0);
        assert_eq!(leading_zero_bits_hex("4000"), 1);
        assert_eq!(leading_zero_bits_hex("2000"), 2);
    }

    #[test]
    fn test_binding_deterministic() {
        let b1 = compute_binding(b"secret", "1.2.3.4", "Mozilla/5.0", "abc");
        let b2 = compute_binding(b"secret", "1.2.3.4", "Mozilla/5.0", "abc");
        assert_eq!(b1, b2);

        let b3 = compute_binding(b"secret", "5.6.7.8", "Mozilla/5.0", "abc");
        assert_ne!(b1, b3);
    }

    #[test]
    fn test_round_prefix_forces_double_block() {
        let binding = compute_binding(b"secret", "1.2.3.4", "Mozilla/5.0", "nonce123");
        let salt = random_hex(16);
        let prefix = build_round_prefix(&binding, &salt, 0);
        // binding=64 hex + ":" + salt=32 hex + ":0:" = 64+1+32+2 = 99 chars
        // Plus nonce (at least 1 char) = 100+ bytes > 64 byte block boundary
        assert!(prefix.len() > 55, "prefix must force double-block: len={}", prefix.len());
    }

    #[test]
    fn test_verify_round_valid() {
        let prefix = "test:salt:0:";
        // Brute-force a valid nonce for difficulty 4
        for i in 0..100000u64 {
            let nonce = format!("{:016x}", i);
            if verify_round(prefix, &nonce, 4) {
                return; // found valid
            }
        }
        panic!("could not find valid nonce in 100k attempts");
    }

    #[test]
    fn test_verify_rejects_non_hex_nonce() {
        assert!(!verify_round("prefix:", "not-hex-zzz", 1));
        assert!(!verify_round("prefix:", "", 1));
    }
}
