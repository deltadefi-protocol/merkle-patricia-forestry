/// Helper functions for Merkle Patricia Forestry

use crate::crypto::{digest, DIGEST_LENGTH};

/// By convention, the hash of empty tries/trees is the NULL_HASH (all zeros)
pub const NULL_HASH: [u8; DIGEST_LENGTH] = [0u8; DIGEST_LENGTH];

/// Turn an object whose keys are hex-digits into a sparse vector.
/// Fill gaps with None values.
///
/// # Arguments
///
/// * `map` - A map of nibble indices (0-15) to values
///
/// # Returns
///
/// A vector of exactly 16 elements, with None for missing indices
pub fn sparse_vector<T: Clone>(map: &[(usize, T)]) -> Vec<Option<T>> {
    let mut vector = vec![None; 16];
    for (k, v) in map {
        assert!(*k <= 15, "key must be between 0 and 15, but it was {}", k);
        vector[*k] = Some(v.clone());
    }
    vector
}

/// Find the prefix common to a list of words. Returns an empty string when
/// there's no common prefix.
///
/// # Arguments
///
/// * `words` - A list of hex-encoded strings
///
/// # Returns
///
/// The common prefix as a string, or empty string if none
pub fn common_prefix(words: &[String]) -> String {
    assert!(!words.is_empty(), "No words to compute prefix from!");

    if words.len() == 1 {
        return words[0].clone();
    }

    let mut prefix = words[0].clone();

    for word in &words[1..] {
        assert!(!word.is_empty(), "Cannot compute common prefix of empty words!");

        // Truncate prefix to word length
        if prefix.len() > word.len() {
            prefix.truncate(word.len());
        }

        // Find first mismatch
        let mut mismatch_idx = 0;
        for (i, (p_char, w_char)) in prefix.chars().zip(word.chars()).enumerate() {
            if p_char != w_char {
                mismatch_idx = i;
                break;
            }
            if i == prefix.len() - 1 {
                mismatch_idx = prefix.len();
            }
        }

        prefix.truncate(mismatch_idx);

        if prefix.is_empty() {
            break;
        }
    }

    prefix
}

/// Test whether a digit is a valid hex digit (0-15)
pub fn is_hex_digit(digit: usize) -> bool {
    digit <= 15
}

/// Convert a hex character into a nibble (0-15)
pub fn nibble(digit: char) -> usize {
    digit.to_digit(16).expect("invalid hex digit") as usize
}

/// Convert a hex-encoded string into a vector of nibbles
///
/// # Arguments
///
/// * `s` - A hex-encoded string
///
/// # Returns
///
/// A vector where each element is a nibble (0-15)
pub fn nibbles(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| nibble(c) as u8)
        .collect()
}

/// Compute the Merkle root of a Sparse-Merkle-Tree formed by a node's children.
///
/// # Arguments
///
/// * `children` - A list of child node hashes (or NULL_HASH for empty)
/// * `size` - Expected size (default 16)
///
/// # Returns
///
/// The merkle root hash
pub fn merkle_root(children: &[[u8; DIGEST_LENGTH]], size: usize) -> [u8; DIGEST_LENGTH] {
    assert_eq!(
        children.len(),
        size,
        "trying to compute an intermediate Merkle root of {} nodes instead of {}",
        children.len(),
        size
    );

    if size == 1 {
        return children[0];
    }

    assert!(
        size >= 2 && size % 2 == 0,
        "trying to compute intermediate Merkle root of an odd number of nodes"
    );

    let mut nodes: Vec<[u8; DIGEST_LENGTH]> = children.to_vec();
    let mut n = nodes.len();

    while n > 1 {
        let mut next_level = Vec::new();
        for i in 0..(n / 2) {
            let mut combined = Vec::with_capacity(2 * DIGEST_LENGTH);
            combined.extend_from_slice(&nodes[2 * i]);
            combined.extend_from_slice(&nodes[2 * i + 1]);
            next_level.push(digest(&combined));
        }
        nodes = next_level;
        n = nodes.len();
    }

    nodes[0]
}

/// Construct a merkle proof for a given non-empty tree.
///
/// # Arguments
///
/// * `nodes` - A list of child nodes to merkleize
/// * `me` - The index of the node we are proving
///
/// # Returns
///
/// A vector of neighbor hashes for the merkle proof
pub fn merkle_proof(
    nodes: &[[u8; DIGEST_LENGTH]],
    me: usize,
) -> Vec<[u8; DIGEST_LENGTH]> {
    assert!(nodes.len() > 1 && nodes.len() % 2 == 0);
    assert!(me < nodes.len());

    let mut neighbors = Vec::new();
    let mut pivot = 8;
    let mut n = 8;

    let me = me;

    loop {
        if me < pivot {
            neighbors.push(merkle_root(&nodes[pivot..pivot + n], n));
            pivot -= n >> 1;
        } else {
            neighbors.push(merkle_root(&nodes[(pivot - n)..pivot], n));
            pivot += n >> 1;
        }
        n >>= 1;

        if n < 1 {
            break;
        }
    }

    neighbors
}

/// Turn any key into a path of nibbles by hashing it first.
///
/// # Arguments
///
/// * `key` - The key to convert
///
/// # Returns
///
/// A hex-encoded string of the hash
pub fn into_path(key: &[u8]) -> String {
    hex::encode(digest(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_hash() {
        assert_eq!(NULL_HASH.len(), DIGEST_LENGTH);
        assert!(NULL_HASH.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_sparse_vector() {
        let map = vec![(1, "foo"), (3, "bar")];
        let vec = sparse_vector(&map);
        assert_eq!(vec.len(), 16);
        assert_eq!(vec[1], Some("foo"));
        assert_eq!(vec[3], Some("bar"));
        assert_eq!(vec[0], None);
        assert_eq!(vec[2], None);
    }

    #[test]
    #[should_panic(expected = "No words to compute prefix from!")]
    fn test_common_prefix_empty_words() {
        // JavaScript test: should throw error for empty array []
        let words: Vec<String> = vec![];
        common_prefix(&words);
    }

    #[test]
    #[should_panic(expected = "Cannot compute common prefix of empty words!")]
    fn test_common_prefix_empty_word() {
        // JavaScript test: should throw error for ['merkle-patricia-trie', '']
        let words = vec!["merkle-patricia-trie".to_string(), "".to_string()];
        common_prefix(&words);
    }

    #[test]
    fn test_common_prefix_identical() {
        let words = vec![
            "merkle-patricia-trie".to_string(),
            "merkle-patricia-trie".to_string(),
        ];
        assert_eq!(common_prefix(&words), "merkle-patricia-trie");
    }

    #[test]
    fn test_common_prefix_partial() {
        let words = vec![
            "do".to_string(),
            "dog".to_string(),
            "dogs".to_string(),
        ];
        assert_eq!(common_prefix(&words), "do");
    }

    #[test]
    fn test_common_prefix_none() {
        let words = vec![
            "dog".to_string(),
            "cat".to_string(),
            "bird".to_string(),
        ];
        assert_eq!(common_prefix(&words), "");
    }

    #[test]
    fn test_common_prefix_last_word_is_prefix() {
        // Test when the shortest word is at the end
        let words = vec![
            "dogs".to_string(),
            "dog".to_string(),
            "do".to_string(),
        ];
        assert_eq!(common_prefix(&words), "do");
    }

    #[test]
    fn test_common_prefix_anywhere() {
        // Test prefix extraction when shortest word is in the middle
        let words = vec![
            "carda".to_string(),
            "cardano".to_string(),
            "card".to_string(),
            "cardinal".to_string(),
        ];
        assert_eq!(common_prefix(&words), "card");
    }

    #[test]
    fn test_nibble() {
        assert_eq!(nibble('0'), 0);
        assert_eq!(nibble('9'), 9);
        assert_eq!(nibble('a'), 10);
        assert_eq!(nibble('f'), 15);
    }

    #[test]
    fn test_nibbles() {
        let result = nibbles("ab");
        assert_eq!(result, vec![10, 11]);

        let result2 = nibbles("0102");
        assert_eq!(result2, vec![0, 1, 0, 2]);
    }

    #[test]
    fn test_merkle_root_null_hashes() {
        // Test with 1 null hash
        let result = merkle_root(&[NULL_HASH], 1);
        assert_eq!(result, NULL_HASH);

        // Test with 2 null hashes
        let result = merkle_root(&[NULL_HASH, NULL_HASH], 2);
        assert_eq!(
            hex::encode(result),
            "0eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f9761"
        );

        // Test with 4 null hashes
        let nodes = vec![NULL_HASH; 4];
        let result = merkle_root(&nodes, 4);
        assert_eq!(
            hex::encode(result),
            "85c09af929492a871e4fae32d9d5c36e352471cd659bcdb61de08f1722acc3b1"
        );

        // Test with 8 null hashes
        let nodes = vec![NULL_HASH; 8];
        let result = merkle_root(&nodes, 8);
        assert_eq!(
            hex::encode(result),
            "b22df1a126b5ba4e33c16fd6157507610e55ffce20dae7ac44cae168a463612a"
        );
    }

    #[test]
    fn test_into_path() {
        let key = b"test";
        let path = into_path(key);
        assert_eq!(path.len(), 64); // 32 bytes = 64 hex chars
        // Verify it's valid hex
        assert!(path.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
