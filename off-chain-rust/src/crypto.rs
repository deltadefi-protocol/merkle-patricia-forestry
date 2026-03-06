/// Cryptographic utilities for Merkle Patricia Forestry
/// Uses Blake2b with 32-byte output to match the JavaScript implementation

use blake2::{Blake2b, Digest};

/// Size of the digest of the underlying hash algorithm (32 bytes)
pub const DIGEST_LENGTH: usize = 32;

/// Compute a hash digest of the given message buffer.
///
/// # Arguments
///
/// * `msg` - Payload to hash
///
/// # Returns
///
/// A 32-byte Blake2b hash digest
pub fn digest(msg: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut hasher = Blake2b::<blake2::digest::consts::U32>::new();
    hasher.update(msg);
    let result = hasher.finalize();
    let mut output = [0u8; DIGEST_LENGTH];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_length() {
        let msg = b"hello world";
        let hash = digest(msg);
        assert_eq!(hash.len(), DIGEST_LENGTH);
    }

    #[test]
    fn test_digest_deterministic() {
        let msg = b"test message";
        let hash1 = digest(msg);
        let hash2 = digest(msg);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_digest_different_inputs() {
        let hash1 = digest(b"foo");
        let hash2 = digest(b"bar");
        assert_ne!(hash1, hash2);
    }
}
