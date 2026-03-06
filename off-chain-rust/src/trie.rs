/// Merkle Patricia Forestry Trie implementation
/// A modified Merkle Patricia Trie of radix 16 with Sparse Merkle Trees for neighbors

use crate::cbor;
use crate::crypto::{digest, DIGEST_LENGTH};
use crate::helpers::{
    common_prefix, into_path, merkle_proof, merkle_root, nibble, nibbles, NULL_HASH,
};
use crate::store::{Store, StoreError};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrieError {
    #[error("Element already in the trie at {0}")]
    AlreadyExists(String),
    #[error("Element at path {0} not in trie: {1}")]
    NotInTrie(String, String),
    #[error("Cannot walk empty trie with path {0}")]
    CannotWalkEmptyTrie(String),
    #[error("Store error: {0}")]
    StoreError(#[from] StoreError),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

pub type Result<T> = std::result::Result<T, TrieError>;

const ROOT_KEY: &str = "__root__";

/// A Merkle Patricia Forestry Trie
#[derive(Clone, Debug)]
pub struct Trie {
    pub hash: Option<[u8; DIGEST_LENGTH]>,
    pub prefix: String,
    pub size: usize,
    pub store: Store,
    pub is_root: bool,
}

impl Trie {
    /// Create a new empty trie
    pub fn new(store: Store) -> Self {
        Trie {
            hash: None,
            prefix: String::new(),
            size: 0,
            store,
            is_root: false,
        }
    }

    /// Check if trie is empty
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Save the trie to the store
    pub fn save(&self, previous_hash: Option<[u8; DIGEST_LENGTH]>) -> Result<()> {
        if let Some(prev) = previous_hash {
            self.store.del(&prev);
        }

        if self.is_root {
            let root_hash = self.hash.unwrap_or(NULL_HASH);
            self.store.put(ROOT_KEY.as_bytes(), &hex::encode(root_hash));
        }

        Ok(())
    }

    /// Load a trie from the store
    pub fn load(store: Store) -> Result<TrieNode> {
        let root_hex = store.get(ROOT_KEY.as_bytes())?;
        let root_hash = hex::decode(&root_hex)
            .map_err(|_| TrieError::InvalidOperation("Invalid root hash".to_string()))?;

        if root_hash == NULL_HASH {
            let mut trie = Trie::new(store);
            trie.is_root = true;
            return Ok(TrieNode::Empty(trie));
        }

        let mut hash = [0u8; DIGEST_LENGTH];
        hash.copy_from_slice(&root_hash);

        let mut node = TrieNode::deserialize(&hash, &store)?;
        match &mut node {
            TrieNode::Leaf(ref mut leaf) => {
                leaf.is_root = true;
            }
            TrieNode::Branch(ref mut branch) => {
                branch.is_root = true;
            }
            _ => {}
        }

        Ok(node)
    }

    /// Build a trie from a list of key-value pairs
    pub fn from_list(pairs: &[(Vec<u8>, Vec<u8>)], store: Store) -> Result<TrieNode> {
        let paths: Vec<(String, Vec<u8>, Vec<u8>)> = pairs
            .iter()
            .map(|(k, v)| (into_path(k), k.clone(), v.clone()))
            .collect();

        let node = Self::from_list_recursive(&paths, &store)?;

        // Mark as root and save
        match node {
            TrieNode::Empty(mut trie) => {
                trie.is_root = true;
                trie.save(None)?;
                Ok(TrieNode::Empty(trie))
            }
            TrieNode::Leaf(mut leaf) => {
                leaf.is_root = true;
                leaf.save(None)?;
                Ok(TrieNode::Leaf(leaf))
            }
            TrieNode::Branch(mut branch) => {
                branch.is_root = true;
                branch.save(None)?;
                Ok(TrieNode::Branch(branch))
            }
        }
    }

    fn from_list_recursive(
        paths: &[(String, Vec<u8>, Vec<u8>)],
        store: &Store,
    ) -> Result<TrieNode> {
        if paths.is_empty() {
            return Ok(TrieNode::Empty(Trie::new((*store).clone())));
        }

        // Find common prefix
        let path_strs: Vec<String> = paths.iter().map(|(p, _, _)| p.clone()).collect();
        let prefix = common_prefix(&path_strs);

        // If only one element, create a leaf
        if paths.len() == 1 {
            let (_path, key, value) = &paths[0];
            return Ok(TrieNode::Leaf(Leaf::new(
                prefix,
                key.clone(),
                value.clone(),
                (*store).clone(),
            )?));
        }

        // Create branch - strip common prefix and group by first remaining nibble
        let mut groups: [Vec<(String, Vec<u8>, Vec<u8>)>; 16] = Default::default();

        for (path, key, value) in paths {
            let remaining = &path[prefix.len()..];
            if remaining.is_empty() {
                return Err(TrieError::InvalidOperation(
                    "Empty path after stripping prefix".to_string(),
                ));
            }

            let first_nibble = nibble(remaining.chars().next().unwrap());
            groups[first_nibble].push((remaining[1..].to_string(), key.clone(), value.clone()));
        }

        // Recursively build children
        let mut children = Vec::new();
        for group in groups.iter() {
            if group.is_empty() {
                children.push(None);
            } else {
                let child = Self::from_list_recursive(group, store)?;
                children.push(Some(child));
            }
        }

        Ok(TrieNode::Branch(Branch::new(prefix, children, store.clone())?))
    }

    /// Insert a key-value pair into the trie
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let path = into_path(key);

        // If empty, convert to leaf
        if self.is_empty() {
            let leaf = Leaf::new(path, key.to_vec(), value.to_vec(), self.store.clone())?;
            *self = Trie {
                hash: leaf.hash,
                prefix: leaf.prefix.clone(),
                size: 1,
                store: self.store.clone(),
                is_root: self.is_root,
            };
            return Ok(());
        }

        Err(TrieError::InvalidOperation(
            "Cannot insert into non-empty base Trie - use Leaf or Branch".to_string(),
        ))
    }

    /// Delete a key from the trie
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        Err(TrieError::NotInTrie(
            hex::encode(key),
            "not in trie".to_string(),
        ))
    }

    /// Get a value by key
    pub fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.is_empty() {
            return Ok(None);
        }
        Err(TrieError::InvalidOperation(
            "Cannot get from base Trie - use child_at or proper node type".to_string(),
        ))
    }

    /// Generate a proof for a given key
    pub fn prove(&self, _key: &[u8], _allow_missing: bool) -> Result<Proof> {
        if self.is_empty() {
            return Err(TrieError::CannotWalkEmptyTrie(hex::encode(_key)));
        }
        Err(TrieError::InvalidOperation(
            "Cannot prove from base Trie".to_string(),
        ))
    }

    /// Walk the trie to generate a proof
    fn walk(&self, _path: &str) -> Result<Proof> {
        Err(TrieError::CannotWalkEmptyTrie(_path.to_string()))
    }
}

/// A Leaf node in the trie
#[derive(Clone, Debug)]
pub struct Leaf {
    pub hash: Option<[u8; DIGEST_LENGTH]>,
    pub prefix: String,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub size: usize,
    pub store: Store,
    pub is_root: bool,
}

impl Leaf {
    pub fn new(suffix: String, key: Vec<u8>, value: Vec<u8>, store: Store) -> Result<Self> {
        // Verify suffix matches the key
        let key_hash = into_path(&key);
        if !key_hash.ends_with(&suffix) {
            return Err(TrieError::InvalidOperation(format!(
                "The suffix {} isn't a valid extension of {}",
                suffix,
                hex::encode(&key)
            )));
        }

        let value_hash = digest(&value);
        let hash = Self::compute_hash(&suffix, &value_hash);

        let mut leaf = Leaf {
            hash: Some(hash),
            prefix: suffix,
            key,
            value,
            size: 1,
            store,
            is_root: false,
        };

        leaf.save_node()?;
        Ok(leaf)
    }

    fn compute_hash(prefix: &str, value_hash: &[u8; DIGEST_LENGTH]) -> [u8; DIGEST_LENGTH] {
        let is_odd = prefix.len() % 2 != 0;

        let mut parts = Vec::new();

        // Head marker
        if is_odd {
            parts.push(0x00);
            parts.extend_from_slice(&[nibble(prefix.chars().next().unwrap()) as u8]);
        } else {
            parts.push(0xFF);
        }

        // Tail (remaining prefix as bytes)
        let tail_start = if is_odd { 1 } else { 0 };
        let tail_hex = &prefix[tail_start..];
        if !tail_hex.is_empty() {
            parts.extend_from_slice(
                &hex::decode(tail_hex).expect("Invalid hex in prefix")
            );
        }

        // Value hash
        parts.extend_from_slice(value_hash);

        digest(&parts)
    }

    fn save_node(&mut self) -> Result<()> {
        let value_hash = digest(&self.value);
        self.hash = Some(Self::compute_hash(&self.prefix, &value_hash));

        let serialized = self.serialize();
        self.store
            .put(&self.hash.unwrap(), &serialized);

        Ok(())
    }

    pub fn save(&mut self, previous_hash: Option<[u8; DIGEST_LENGTH]>) -> Result<()> {
        self.save_node()?;

        if let Some(prev) = previous_hash {
            self.store.del(&prev);
        }

        if self.is_root {
            let root_hash = self.hash.unwrap();
            self.store.put(ROOT_KEY.as_bytes(), &hex::encode(root_hash));
        }

        Ok(())
    }

    fn serialize(&self) -> String {
        let obj = serde_json::json!({
            "__kind": "Leaf",
            "prefix": self.prefix,
            "key": hex::encode(&self.key),
            "value": hex::encode(&self.value),
        });
        obj.to_string()
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if self.key == key {
            return Err(TrieError::AlreadyExists("already in trie".to_string()));
        }

        let this_path = self.prefix.clone();
        let new_path_full = into_path(key);
        let new_path = &new_path_full[new_path_full.len() - this_path.len()..];

        if this_path == new_path {
            return Err(TrieError::AlreadyExists(format!(
                "element already in the trie at {}",
                hex::encode(key)
            )));
        }

        // Find common prefix between this and new leaf
        let prefix = common_prefix(&[this_path.clone(), new_path.to_string()]);

        let this_nibble = nibble(this_path[prefix.len()..].chars().next().unwrap());
        let new_nibble = nibble(new_path[prefix.len()..].chars().next().unwrap());

        if this_nibble == new_nibble {
            return Err(TrieError::InvalidOperation(
                "Nibbles should differ after common prefix".to_string(),
            ));
        }

        // Create two new leaves
        let this_leaf = Leaf::new(
            this_path[prefix.len() + 1..].to_string(),
            self.key.clone(),
            self.value.clone(),
            self.store.clone(),
        )?;

        let new_leaf = Leaf::new(
            new_path[prefix.len() + 1..].to_string(),
            key.to_vec(),
            value.to_vec(),
            self.store.clone(),
        )?;

        // Create branch with both leaves
        let mut children = vec![None; 16];
        children[this_nibble] = Some(TrieNode::Leaf(this_leaf));
        children[new_nibble] = Some(TrieNode::Leaf(new_leaf));

        // This doesn't actually transform self, but we can't do that in Rust like JS
        // The caller needs to handle the transformation
        Err(TrieError::InvalidOperation(
            "Leaf needs to be upgraded to Branch - not supported in-place in Rust".to_string(),
        ))
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if self.key != key {
            return Err(TrieError::NotInTrie(
                hex::encode(key),
                "key mismatch".to_string(),
            ));
        }

        // Convert to empty trie
        // In JS this mutates in place, in Rust the caller handles it
        Ok(())
    }

    /// Generate a proof for a given key
    pub fn prove(&self, key: &[u8], allow_missing: bool) -> Result<Proof> {
        let path = into_path(key);

        // Check if this is the exact key
        if self.key == key {
            // Membership proof
            return Ok(Proof::new(path, Some(self.value.clone()), vec![]));
        }

        // If allow_missing, check if we can prove non-membership
        if allow_missing {
            // For non-membership, the key should hash to a different path
            // but we can only prove it if it would have been in this location
            // This is a leaf, so any different key at this location proves non-membership
            return Ok(Proof::new(path, None, vec![]));
        }

        Err(TrieError::NotInTrie(
            hex::encode(key),
            "not in trie".to_string(),
        ))
    }

    /// Walk the trie to generate a proof
    fn walk(&self, path: &str) -> Result<Proof> {
        // For a leaf, the path should match our prefix exactly for membership
        // If it doesn't match, this is a non-membership proof scenario
        if !path.starts_with(&self.prefix) {
            // Path diverges from this leaf - this can be used for non-membership proof
            return Ok(Proof::new(path.to_string(), None, vec![]));
        }

        let value = if path == self.prefix {
            Some(self.value.clone())
        } else {
            None
        };

        Ok(Proof::new(into_path(&self.key), value, vec![]))
    }
}

/// A Branch node in the trie
#[derive(Clone, Debug)]
pub struct Branch {
    pub hash: Option<[u8; DIGEST_LENGTH]>,
    pub prefix: String,
    pub children: Vec<Option<TrieNode>>,
    pub size: usize,
    pub store: Store,
    pub is_root: bool,
}

impl Branch {
    pub fn new(prefix: String, children: Vec<Option<TrieNode>>, store: Store) -> Result<Self> {
        assert_eq!(children.len(), 16, "children must have exactly 16 elements");

        // Count non-empty children
        let non_empty = children.iter().filter(|c| c.is_some()).count();
        assert!(
            non_empty >= 2,
            "Branch must have at least 2 children, found {}",
            non_empty
        );

        // Calculate size
        let size = children
            .iter()
            .map(|c| c.as_ref().map(|n| n.size()).unwrap_or(0))
            .sum();

        // Compute hash
        let child_hashes: Vec<[u8; DIGEST_LENGTH]> = children
            .iter()
            .map(|c| c.as_ref().and_then(|n| n.hash()).unwrap_or(NULL_HASH))
            .collect();
        let root = merkle_root(&child_hashes, 16);
        let hash = Self::compute_hash(&prefix, &root);

        let mut branch = Branch {
            hash: Some(hash),
            prefix,
            children,
            size,
            store,
            is_root: false,
        };

        branch.save_node()?;
        Ok(branch)
    }

    fn compute_hash(prefix: &str, root: &[u8; DIGEST_LENGTH]) -> [u8; DIGEST_LENGTH] {
        let prefix_nibbles = nibbles(prefix);
        let mut combined = Vec::new();
        combined.extend_from_slice(&prefix_nibbles);
        combined.extend_from_slice(root);
        digest(&combined)
    }

    fn save_node(&mut self) -> Result<()> {
        // Compute hash from children
        let child_hashes: Vec<[u8; DIGEST_LENGTH]> = self
            .children
            .iter()
            .map(|c| c.as_ref().and_then(|n| n.hash()).unwrap_or(NULL_HASH))
            .collect();
        let root = merkle_root(&child_hashes, 16);
        self.hash = Some(Self::compute_hash(&self.prefix, &root));

        let serialized = self.serialize();
        self.store.put(&self.hash.unwrap(), &serialized);

        Ok(())
    }

    pub fn save(&mut self, previous_hash: Option<[u8; DIGEST_LENGTH]>) -> Result<()> {
        self.save_node()?;

        if let Some(prev) = previous_hash {
            self.store.del(&prev);
        }

        if self.is_root {
            let root_hash = self.hash.unwrap();
            self.store
                .put(ROOT_KEY.as_bytes(), &hex::encode(root_hash));
        }

        Ok(())
    }

    fn serialize(&self) -> String {
        let child_hashes: Vec<Option<String>> = self
            .children
            .iter()
            .map(|c| {
                c.as_ref()
                    .and_then(|n| n.hash())
                    .map(|h| hex::encode(h))
            })
            .collect();

        let obj = serde_json::json!({
            "__kind": "Branch",
            "prefix": self.prefix,
            "children": child_hashes,
            "size": self.size,
        });
        obj.to_string()
    }

    /// Generate a proof for a given key
    pub fn prove(&self, key: &[u8], allow_missing: bool) -> Result<Proof> {
        let path = into_path(key);

        // Try regular walk first
        match self.walk_with_missing(&path, false) {
            Ok(proof) => Ok(proof),
            Err(e) if allow_missing && matches!(e, TrieError::NotInTrie(_, _)) => {
                // Generate non-membership proof by temporarily inserting the key
                // Clone the entire trie structure
                let mut temp_trie = TrieNode::Branch(self.clone());
                let original_hash = temp_trie.hash();

                // Insert with empty string value
                let empty_value = b"".to_vec();
                temp_trie.insert(key, &empty_value)?;

                // After insertion, the trie structure may have changed
                // We need to extract the updated branch and use it for proving
                let proof_result = match &temp_trie {
                    TrieNode::Branch(updated_branch) => {
                        // Call walk_with_missing on the updated branch using the SAME path
                        updated_branch.walk_with_missing(&path, false)
                    }
                    TrieNode::Leaf(leaf) => {
                        // If it transformed to a leaf, use leaf's prove
                        leaf.prove(key, false)
                    }
                    _ => {
                        return Err(TrieError::InvalidOperation(
                            "Unexpected trie type after insertion".to_string()
                        ));
                    }
                };

                let mut proof = proof_result?;

                // Set value to None for exclusion proof
                proof.value = None;

                // Delete the key to restore original state
                temp_trie.delete(key)?;

                // Verify hash is restored
                if temp_trie.hash() != original_hash {
                    return Err(TrieError::InvalidOperation(
                        format!("hash mismatch after non-membership proof generation: expected {:?}, got {:?}",
                            original_hash, temp_trie.hash())
                    ));
                }

                Ok(proof)
            }
            Err(e) => Err(e),
        }
    }

    /// Internal prove that doesn't handle allow_missing logic
    fn prove_internal(&self, key: &[u8]) -> Result<Proof> {
        let path = into_path(key);
        self.walk_with_missing(&path, false)
    }

    /// Walk the trie to generate a proof
    fn walk(&self, path: &str) -> Result<Proof> {
        self.walk_with_missing(path, false)
    }

    /// Walk the trie with optional non-membership proof support
    fn walk_with_missing(&self, path: &str, allow_missing: bool) -> Result<Proof> {

        if !path.starts_with(&self.prefix) {
            return Err(TrieError::NotInTrie(
                path.to_string(),
                format!("non-matching prefix {}", self.prefix),
            ));
        }

        let skip = self.prefix.len();
        let remaining_path = &path[skip..];

        if remaining_path.is_empty() {
            return Err(TrieError::NotInTrie(
                path.to_string(),
                "path ends at branch".to_string(),
            ));
        }

        let branch_nibble = nibble(remaining_path.chars().next().unwrap());

        // Load children on demand
        let mut loaded_children = Vec::new();
        for child_opt in &self.children {
            if let Some(child) = child_opt {
                if let Some(hash) = child.hash() {
                    let loaded = TrieNode::deserialize(&hash, &self.store)?;
                    loaded_children.push(Some(loaded));
                } else {
                    loaded_children.push(Some(child.clone()));
                }
            } else {
                loaded_children.push(None);
            }
        }

        // Check if child exists
        if loaded_children[branch_nibble].is_none() {
            if !allow_missing {
                return Err(TrieError::NotInTrie(
                    path.to_string(),
                    format!("no child at branch {}", branch_nibble),
                ));
            }

            // Non-membership proof - just return an empty proof
            // The rewind calls up the stack will build the proof
            return Ok(Proof::new(path.to_string(), None, vec![]));
        }

        let child = loaded_children[branch_nibble].as_ref().unwrap();

        // Recursively walk the child
        let walk_result = match child {
            TrieNode::Leaf(l) => l.walk(&remaining_path[1..]),
            TrieNode::Branch(b) => b.walk_with_missing(&remaining_path[1..], allow_missing),
            TrieNode::Empty(_) => {
                return Err(TrieError::NotInTrie(
                    path.to_string(),
                    "child is empty".to_string(),
                ));
            }
        };

        // Handle the result
        let mut proof = match walk_result {
            Ok(p) => p,
            Err(e) => {
                // If we get NotInTrie error and allow_missing is true,
                // we need to generate a non-membership proof
                if allow_missing && matches!(e, TrieError::NotInTrie(_, _)) {
                    // Return empty proof to be built up by rewind
                    return Ok(Proof::new(path.to_string(), None, vec![]));
                }
                return Err(e);
            }
        };

        proof.rewind(child, skip, &loaded_children)?;

        Ok(proof)
    }

    /// Delete a key from the branch
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        let path = into_path(key);
        self.delete_with_path(key, &path)
    }

    fn delete_with_path(&mut self, key: &[u8], path: &str) -> Result<()> {
        let cursor = self.prefix.len();

        if cursor >= path.len() {
            return Err(TrieError::NotInTrie(
                hex::encode(key),
                "path too short".to_string(),
            ));
        }

        let this_nibble = nibble(path[cursor..].chars().next().unwrap());

        // Load children
        let mut loaded_children = Vec::new();
        for child_opt in self.children.iter() {
            if let Some(child) = child_opt {
                if let Some(hash) = child.hash() {
                    let loaded = TrieNode::deserialize(&hash, &self.store)?;
                    loaded_children.push(Some(loaded));
                } else {
                    loaded_children.push(Some(child.clone()));
                }
            } else {
                loaded_children.push(None);
            }
        }

        // Delete from child
        let child = loaded_children[this_nibble]
            .as_mut()
            .ok_or_else(|| {
                TrieError::NotInTrie(
                    hex::encode(key),
                    format!("no child at nibble {}", this_nibble),
                )
            })?;

        let remaining_path = &path[cursor + 1..];

        match child {
            TrieNode::Leaf(ref mut leaf) => {
                leaf.delete(key)?;
                loaded_children[this_nibble] = None;
            }
            TrieNode::Branch(ref mut branch) => {
                branch.delete_with_path(key, remaining_path)?;
                // After recursively deleting, child might have been collapsed
                // Re-check if it's now a leaf or empty
                if branch.size == 0 {
                    loaded_children[this_nibble] = None;
                }
            }
            TrieNode::Empty(_) => {
                return Err(TrieError::NotInTrie(
                    hex::encode(key),
                    "child is empty".to_string(),
                ));
            }
        }

        self.children = loaded_children;
        self.size -= 1;

        // Save the updated branch
        self.save_node()?;

        Ok(())
    }
}

/// Enum representing any trie node type
#[derive(Clone, Debug)]
pub enum TrieNode {
    Empty(Trie),
    Leaf(Leaf),
    Branch(Branch),
}

impl TrieNode {
    pub fn hash(&self) -> Option<[u8; DIGEST_LENGTH]> {
        match self {
            TrieNode::Empty(t) => t.hash,
            TrieNode::Leaf(l) => l.hash,
            TrieNode::Branch(b) => b.hash,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            TrieNode::Empty(t) => t.size,
            TrieNode::Leaf(l) => l.size,
            TrieNode::Branch(b) => b.size,
        }
    }

    pub fn prefix(&self) -> &str {
        match self {
            TrieNode::Empty(t) => &t.prefix,
            TrieNode::Leaf(l) => &l.prefix,
            TrieNode::Branch(b) => &b.prefix,
        }
    }

    pub fn prove(&self, key: &[u8], allow_missing: bool) -> Result<Proof> {
        match self {
            TrieNode::Empty(_) => {
                if allow_missing {
                    Ok(Proof::new(into_path(key), None, vec![]))
                } else {
                    Err(TrieError::CannotWalkEmptyTrie(hex::encode(key)))
                }
            }
            TrieNode::Leaf(l) => {
                // For leaves, try to prove first
                match l.prove(key, false) {
                    Ok(proof) => Ok(proof),
                    Err(e) if allow_missing && matches!(e, TrieError::NotInTrie(_, _)) => {
                        // Generate non-membership proof
                        // Clone and insert temporarily
                        let mut temp_trie = TrieNode::Leaf(l.clone());
                        let original_hash = temp_trie.hash();

                        let empty_value = b"".to_vec();
                        temp_trie.insert(key, &empty_value)?;

                        let mut proof = temp_trie.prove_internal(key)?;
                        proof.value = None;

                        temp_trie.delete(key)?;

                        // Verify hash is restored
                        if temp_trie.hash() != original_hash {
                            return Err(TrieError::InvalidOperation(
                                "hash mismatch after non-membership proof generation".to_string()
                            ));
                        }

                        Ok(proof)
                    }
                    Err(e) => Err(e),
                }
            }
            TrieNode::Branch(b) => b.prove(key, allow_missing),
        }
    }

    /// Internal prove that doesn't handle allow_missing logic
    fn prove_internal(&self, key: &[u8]) -> Result<Proof> {
        match self {
            TrieNode::Empty(_) => Err(TrieError::CannotWalkEmptyTrie(hex::encode(key))),
            TrieNode::Leaf(l) => l.prove(key, false),
            TrieNode::Branch(b) => b.prove_internal(key),
        }
    }

    fn walk(&self, path: &str) -> Result<Proof> {
        match self {
            TrieNode::Empty(_) => Err(TrieError::CannotWalkEmptyTrie(path.to_string())),
            TrieNode::Leaf(l) => l.walk(path),
            TrieNode::Branch(b) => b.walk(path),
        }
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        match self {
            TrieNode::Empty(_) => Err(TrieError::NotInTrie(
                hex::encode(key),
                "empty trie".to_string(),
            )),
            TrieNode::Leaf(l) => {
                l.delete(key)?;
                // Transform self into Empty
                let store = l.store.clone();
                let is_root = l.is_root;
                *self = TrieNode::Empty(Trie {
                    hash: None,
                    prefix: String::new(),
                    size: 0,
                    store,
                    is_root,
                });
                Ok(())
            }
            TrieNode::Branch(b) => {
                b.delete(key)?;

                // Check if we need to collapse to a leaf
                let non_empty: Vec<_> = b.children
                    .iter()
                    .enumerate()
                    .filter_map(|(i, c)| c.as_ref().map(|child| (i, child.clone())))
                    .collect();

                if non_empty.len() == 1 {
                    let (_, child) = non_empty.into_iter().next().unwrap();
                    *self = child;
                }

                Ok(())
            }
        }
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let path = into_path(key);
        self.insert_with_path(key, value, &path)
    }

    fn insert_with_path(&mut self, key: &[u8], value: &[u8], path: &str) -> Result<()> {
        match self {
            TrieNode::Empty(t) => {
                // Convert to leaf
                let leaf = Leaf::new(path.to_string(), key.to_vec(), value.to_vec(), t.store.clone())?;
                *self = TrieNode::Leaf(leaf);
                Ok(())
            }
            TrieNode::Leaf(l) => {
                // Need to upgrade to branch
                // The leaf has a prefix that represents the remaining path at this depth
                let this_path = &l.prefix;

                // For the new key, we need to extract the suffix that corresponds to this depth
                // We take the last N characters of the full path, where N is the leaf's prefix length
                let new_full_path = into_path(key);
                let new_path = if new_full_path.len() >= this_path.len() {
                    &new_full_path[new_full_path.len() - this_path.len()..]
                } else {
                    return Err(TrieError::InvalidOperation(
                        "New key path is shorter than existing leaf prefix".to_string()
                    ));
                };

                // Find common prefix
                let prefix = common_prefix(&[this_path.to_string(), new_path.to_string()]);

                // Get the nibbles after the common prefix
                let this_nibble = nibble(this_path[prefix.len()..].chars().next().unwrap());
                let new_nibble = nibble(new_path[prefix.len()..].chars().next().unwrap());

                if this_nibble == new_nibble {
                    return Err(TrieError::AlreadyExists(hex::encode(key)));
                }

                // Create two new leaves
                let this_suffix = &this_path[prefix.len() + 1..];
                let new_suffix = &new_path[prefix.len() + 1..];

                let this_leaf = Leaf::new(
                    this_suffix.to_string(),
                    l.key.clone(),
                    l.value.clone(),
                    l.store.clone()
                )?;

                let new_leaf = Leaf::new(
                    new_suffix.to_string(),
                    key.to_vec(),
                    value.to_vec(),
                    l.store.clone()
                )?;

                // Create branch with two children
                let mut children = vec![None; 16];
                children[this_nibble] = Some(TrieNode::Leaf(this_leaf));
                children[new_nibble] = Some(TrieNode::Leaf(new_leaf));

                let branch = Branch::new(prefix, children, l.store.clone())?;
                *self = TrieNode::Branch(branch);

                Ok(())
            }
            TrieNode::Branch(b) => {
                let cursor = b.prefix.len();

                if cursor >= path.len() {
                    return Err(TrieError::AlreadyExists(hex::encode(key)));
                }

                let this_nibble = nibble(path[cursor..].chars().next().unwrap());

                // Load children
                let mut loaded_children = Vec::new();
                for child_opt in b.children.iter() {
                    if let Some(child) = child_opt {
                        if let Some(hash) = child.hash() {
                            let loaded = TrieNode::deserialize(&hash, &b.store)?;
                            loaded_children.push(Some(loaded));
                        } else {
                            loaded_children.push(Some(child.clone()));
                        }
                    } else {
                        loaded_children.push(None);
                    }
                }

                if let Some(ref mut child) = loaded_children[this_nibble] {
                    // Recursively insert with the remaining path (skip current nibble)
                    let remaining_path = &path[cursor + 1..];
                    child.insert_with_path(key, value, remaining_path)?;
                } else {
                    // Create new leaf
                    let remaining_path = &path[cursor + 1..];
                    let leaf = Leaf::new(remaining_path.to_string(), key.to_vec(), value.to_vec(), b.store.clone())?;
                    loaded_children[this_nibble] = Some(TrieNode::Leaf(leaf));
                }

                b.children = loaded_children;
                b.size += 1;
                b.save_node()?;

                Ok(())
            }
        }
    }

    fn deserialize(hash: &[u8; DIGEST_LENGTH], store: &Store) -> Result<Self> {
        let json_str = store.get(hash)?;
        let value: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| TrieError::InvalidOperation(format!("JSON parse error: {}", e)))?;

        let kind = value
            .get("__kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TrieError::InvalidOperation("Missing __kind field".to_string()))?;

        match kind {
            "Leaf" => {
                let prefix = value["prefix"].as_str().unwrap().to_string();
                let key = hex::decode(value["key"].as_str().unwrap()).unwrap();
                let val = hex::decode(value["value"].as_str().unwrap()).unwrap();

                let leaf = Leaf {
                    hash: Some(*hash),
                    prefix,
                    key,
                    value: val,
                    size: 1,
                    store: store.clone(),
                    is_root: false,
                };

                Ok(TrieNode::Leaf(leaf))
            }
            "Branch" => {
                let prefix = value["prefix"].as_str().unwrap().to_string();
                let size = value["size"].as_u64().unwrap() as usize;
                let children_array = value["children"].as_array().unwrap();

                let mut children = Vec::new();
                for child in children_array {
                    if child.is_null() {
                        children.push(None);
                    } else {
                        // Create a placeholder Trie with just the hash
                        // This will be loaded on demand when needed
                        let child_hash_str = child.as_str().unwrap();
                        let child_hash_bytes = hex::decode(child_hash_str).unwrap();
                        let mut child_hash_array = [0u8; DIGEST_LENGTH];
                        child_hash_array.copy_from_slice(&child_hash_bytes);

                        // Create an Empty Trie node with just the hash as a placeholder
                        let placeholder = TrieNode::Empty(Trie {
                            hash: Some(child_hash_array),
                            prefix: String::new(),
                            size: 0,
                            store: store.clone(),
                            is_root: false,
                        });
                        children.push(Some(placeholder));
                    }
                }

                let branch = Branch {
                    hash: Some(*hash),
                    prefix,
                    children,
                    size,
                    store: store.clone(),
                    is_root: false,
                };

                Ok(TrieNode::Branch(branch))
            }
            _ => Err(TrieError::InvalidOperation(format!(
                "Unknown node kind: {}",
                kind
            ))),
        }
    }
}

/// A proof of inclusion or exclusion for a value in the trie
#[derive(Debug)]
pub struct Proof {
    path: String,
    pub value: Option<Vec<u8>>,
    steps: Vec<ProofStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProofStep {
    Branch {
        skip: usize,
        neighbors: String, // Hex-encoded concatenated hashes
    },
    Fork {
        skip: usize,
        neighbor: ForkNeighbor,
    },
    Leaf {
        skip: usize,
        neighbor: LeafNeighbor,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForkNeighbor {
    pub nibble: usize,
    pub prefix: String,
    pub root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafNeighbor {
    pub key: String,
    pub value: String,
}

impl Proof {
    pub fn new(path: String, value: Option<Vec<u8>>, steps: Vec<ProofStep>) -> Self {
        Proof { path, value, steps }
    }

    pub fn set_value(&mut self, value: Option<Vec<u8>>) {
        self.value = value;
    }

    pub fn clone(&self) -> Self {
        Proof {
            path: self.path.clone(),
            value: self.value.clone(),
            steps: self.steps.clone(),
        }
    }

    /// Add a proof step by rewinding one level up the trie
    pub fn rewind(
        &mut self,
        target: &TrieNode,
        skip: usize,
        children: &[Option<TrieNode>],
    ) -> Result<()> {
        use crate::helpers::{merkle_proof, merkle_root, nibbles};

        let target_hash = target.hash().unwrap_or(NULL_HASH);
        let me = children
            .iter()
            .position(|c| c.as_ref().and_then(|n| n.hash()).unwrap_or(NULL_HASH) == target_hash)
            .ok_or_else(|| TrieError::InvalidOperation("target not in children".to_string()))?;

        let non_empty_neighbors: Vec<_> = children
            .iter()
            .enumerate()
            .filter(|(ix, c)| c.is_some() && *ix != me)
            .collect();

        if non_empty_neighbors.len() == 1 {
            let (_, neighbor) = non_empty_neighbors[0];
            let neighbor = neighbor.as_ref().unwrap();

            match neighbor {
                TrieNode::Leaf(leaf) => {
                    self.steps.insert(
                        0,
                        ProofStep::Leaf {
                            skip,
                            neighbor: LeafNeighbor {
                                key: into_path(&leaf.key),
                                value: hex::encode(digest(&leaf.value)),
                            },
                        },
                    );
                }
                TrieNode::Branch(branch) => {
                    let nibble_idx = children
                        .iter()
                        .position(|c| {
                            c.as_ref()
                                .and_then(|n| n.hash())
                                .map(|h| h == branch.hash.unwrap())
                                .unwrap_or(false)
                        })
                        .unwrap();

                    // Compute merkle root of branch's children
                    let child_hashes: Vec<[u8; DIGEST_LENGTH]> = branch
                        .children
                        .iter()
                        .map(|c| c.as_ref().and_then(|n| n.hash()).unwrap_or(NULL_HASH))
                        .collect();
                    let root = merkle_root(&child_hashes, 16);

                    self.steps.insert(
                        0,
                        ProofStep::Fork {
                            skip,
                            neighbor: ForkNeighbor {
                                nibble: nibble_idx,
                                prefix: hex::encode(nibbles(&branch.prefix)),
                                root: hex::encode(root),
                            },
                        },
                    );
                }
                TrieNode::Empty(_) => {
                    return Err(TrieError::InvalidOperation(
                        "neighbor cannot be empty".to_string(),
                    ));
                }
            }
        } else {
            // Multiple neighbors - use merkle proof
            let child_hashes: Vec<[u8; DIGEST_LENGTH]> = children
                .iter()
                .map(|c| c.as_ref().and_then(|n| n.hash()).unwrap_or(NULL_HASH))
                .collect();

            let neighbors = merkle_proof(&child_hashes, me);
            let neighbors_hex: String = neighbors.iter().map(|h| hex::encode(h)).collect();

            self.steps.insert(
                0,
                ProofStep::Branch {
                    skip,
                    neighbors: neighbors_hex,
                },
            );
        }

        Ok(())
    }

    pub fn verify(&self, including_item: bool) -> Result<Option<[u8; DIGEST_LENGTH]>> {
        if including_item && self.value.is_none() {
            return Err(TrieError::InvalidOperation(
                "attempted to verify an inclusion proof without value".to_string(),
            ));
        }

        if self.steps.is_empty() {
            if including_item {
                let value_hash = digest(&self.value.as_ref().unwrap());
                return Ok(Some(Leaf::compute_hash(&self.path, &value_hash)));
            } else {
                return Ok(None);
            }
        }

        let result = self.verify_loop(0, 0, including_item)?;
        Ok(result)
    }

    fn verify_loop(
        &self,
        cursor: usize,
        step_ix: usize,
        including_item: bool,
    ) -> Result<Option<[u8; DIGEST_LENGTH]>> {
        use crate::helpers::{merkle_root, nibbles, sparse_vector};

        let step = self.steps.get(step_ix);

        // Terminal case - reached the leaf
        if step.is_none() {
            if !including_item {
                return Ok(None);
            }

            let suffix = &self.path[cursor..];
            let value = self.value.as_ref().ok_or_else(|| {
                TrieError::InvalidOperation(format!("no value at path {}", &self.path[..cursor]))
            })?;

            return Ok(Some(Leaf::compute_hash(suffix, &digest(value))));
        }

        let step = step.unwrap();
        let is_last_step = step_ix + 1 >= self.steps.len();

        let skip = match step {
            ProofStep::Branch { skip, .. } => *skip,
            ProofStep::Fork { skip, ..} => *skip,
            ProofStep::Leaf { skip, .. } => *skip,
        };

        let next_cursor = cursor + 1 + skip;
        let me_opt = self.verify_loop(next_cursor, step_ix + 1, including_item)?;

        let this_nibble = nibble(self.path[next_cursor - 1..].chars().next().unwrap());

        match step {
            ProofStep::Branch { neighbors, .. } => {
                // In exclusion mode, me can be None at the last step - use NULL_HASH
                let me = me_opt.unwrap_or(NULL_HASH);

                // Parse neighbor hashes (4 hashes concatenated)
                let neighbors_bytes = hex::decode(neighbors)
                    .map_err(|_| TrieError::InvalidOperation("Invalid hex in neighbors".to_string()))?;

                let mut neighbor_hashes = Vec::new();
                for i in 0..4 {
                    if i * DIGEST_LENGTH < neighbors_bytes.len() {
                        let end = ((i + 1) * DIGEST_LENGTH).min(neighbors_bytes.len());
                        let mut hash = [0u8; DIGEST_LENGTH];
                        let slice = &neighbors_bytes[i * DIGEST_LENGTH..end];
                        if slice.len() == DIGEST_LENGTH {
                            hash.copy_from_slice(slice);
                            neighbor_hashes.push(hash);
                        } else {
                            neighbor_hashes.push(NULL_HASH);
                        }
                    } else {
                        neighbor_hashes.push(NULL_HASH);
                    }
                }

                // Build merkle tree according to nibble position
                let merkle = self.compute_branch_merkle(&me, &neighbor_hashes, this_nibble)?;

                let prefix = &self.path[cursor..next_cursor - 1];
                let root = Branch::compute_hash(prefix, &merkle);
                Ok(Some(root))
            }
            ProofStep::Fork { neighbor, .. } => {
                if !including_item && is_last_step {
                    // Reconstruct the neighbor before fork
                    // In JS: prefix is either [neighbor.nibble, neighbor.prefix]
                    // or [nibbles(path.slice(cursor, cursor + skip)), neighbor.nibble, neighbor.prefix]
                    let neighbor_prefix_bytes = hex::decode(&neighbor.prefix)
                        .map_err(|_| TrieError::InvalidOperation("Invalid hex in prefix".to_string()))?;
                    let neighbor_root_bytes = hex::decode(&neighbor.root)
                        .map_err(|_| TrieError::InvalidOperation("Invalid hex in root".to_string()))?;

                    let mut combined = Vec::new();

                    // Add common prefix if skip > 0
                    if skip > 0 {
                        combined.extend_from_slice(&nibbles(&self.path[cursor..cursor + skip]));
                    }

                    // Add neighbor nibble
                    combined.push(neighbor.nibble as u8);

                    // Add neighbor's own prefix
                    combined.extend_from_slice(&neighbor_prefix_bytes);

                    // Add neighbor root
                    combined.extend_from_slice(&neighbor_root_bytes);

                    return Ok(Some(digest(&combined)));
                }

                // In exclusion mode at non-last steps, me can be None - use NULL_HASH
                let me = me_opt.unwrap_or(NULL_HASH);

                if neighbor.nibble == this_nibble {
                    return Err(TrieError::InvalidOperation(
                        "neighbor nibble equals this nibble".to_string(),
                    ));
                }

                // Build sparse vector with both branches
                let neighbor_root_bytes = hex::decode(&neighbor.root)
                    .map_err(|_| TrieError::InvalidOperation("Invalid hex in root".to_string()))?;
                let mut neighbor_root_hash = [0u8; DIGEST_LENGTH];
                neighbor_root_hash.copy_from_slice(&neighbor_root_bytes[..DIGEST_LENGTH]);

                let neighbor_prefix_bytes = hex::decode(&neighbor.prefix)
                    .map_err(|_| TrieError::InvalidOperation("Invalid hex in prefix".to_string()))?;

                let mut neighbor_combined = Vec::new();
                neighbor_combined.extend_from_slice(&neighbor_prefix_bytes);
                neighbor_combined.extend_from_slice(&neighbor_root_hash);
                let neighbor_hash = digest(&neighbor_combined);

                let nodes = sparse_vector(&[
                    (this_nibble, me),
                    (neighbor.nibble, neighbor_hash),
                ]);

                let child_hashes: Vec<[u8; DIGEST_LENGTH]> = nodes
                    .iter()
                    .map(|n| n.unwrap_or(NULL_HASH))
                    .collect();

                let merkle = merkle_root(&child_hashes, 16);
                let prefix = &self.path[cursor..next_cursor - 1];
                let root = Branch::compute_hash(prefix, &merkle);
                Ok(Some(root))
            }
            ProofStep::Leaf { neighbor, .. } => {
                let neighbor_path = &neighbor.key;

                if !neighbor_path.starts_with(&self.path[..cursor]) {
                    return Err(TrieError::InvalidOperation(
                        "neighbor path doesn't match".to_string(),
                    ));
                }

                let neighbor_nibble = nibble(neighbor_path[next_cursor - 1..].chars().next().unwrap());

                if neighbor_nibble == this_nibble {
                    return Err(TrieError::InvalidOperation(
                        "neighbor nibble equals this nibble".to_string(),
                    ));
                }

                if !including_item && is_last_step {
                    // Return just the neighbor leaf hash
                    let suffix = &neighbor_path[cursor..];
                    let value = hex::decode(&neighbor.value)
                        .map_err(|_| TrieError::InvalidOperation("Invalid hex in value".to_string()))?;
                    let mut value_hash = [0u8; DIGEST_LENGTH];
                    value_hash.copy_from_slice(&value[..DIGEST_LENGTH]);
                    return Ok(Some(Leaf::compute_hash(suffix, &value_hash)));
                }

                // In exclusion mode at non-last steps, me can be None - use NULL_HASH
                let me = me_opt.unwrap_or(NULL_HASH);

                let suffix = &neighbor_path[next_cursor..];
                let value = hex::decode(&neighbor.value)
                    .map_err(|_| TrieError::InvalidOperation("Invalid hex in value".to_string()))?;
                let mut value_hash = [0u8; DIGEST_LENGTH];
                value_hash.copy_from_slice(&value[..DIGEST_LENGTH]);
                let neighbor_leaf_hash = Leaf::compute_hash(suffix, &value_hash);

                let nodes = sparse_vector(&[
                    (this_nibble, me),
                    (neighbor_nibble, neighbor_leaf_hash),
                ]);

                let child_hashes: Vec<[u8; DIGEST_LENGTH]> = nodes
                    .iter()
                    .map(|n| n.unwrap_or(NULL_HASH))
                    .collect();

                let merkle = merkle_root(&child_hashes, 16);
                let prefix = &self.path[cursor..next_cursor - 1];
                let root = Branch::compute_hash(prefix, &merkle);
                Ok(Some(root))
            }
        }
    }

    fn compute_branch_merkle(
        &self,
        me: &[u8; DIGEST_LENGTH],
        neighbors: &[[u8; DIGEST_LENGTH]],
        nibble_idx: usize,
    ) -> Result<[u8; DIGEST_LENGTH]> {
        // Helper to hash two nodes
        let h = |left: [u8; DIGEST_LENGTH], right: [u8; DIGEST_LENGTH]| -> [u8; DIGEST_LENGTH] {
            let mut combined = Vec::new();
            combined.extend_from_slice(&left);
            combined.extend_from_slice(&right);
            digest(&combined)
        };

        let lvl1 = neighbors.get(0).cloned().unwrap_or(NULL_HASH);
        let lvl2 = neighbors.get(1).cloned().unwrap_or(NULL_HASH);
        let lvl3 = neighbors.get(2).cloned().unwrap_or(NULL_HASH);
        let lvl4 = neighbors.get(3).cloned().unwrap_or(NULL_HASH);

        // Compute merkle root based on nibble position (0-15)
        let result = match nibble_idx {
            0 => h(h(h(h(*me, lvl4), lvl3), lvl2), lvl1),
            1 => h(h(h(h(lvl4, *me), lvl3), lvl2), lvl1),
            2 => h(h(h(lvl3, h(*me, lvl4)), lvl2), lvl1),
            3 => h(h(h(lvl3, h(lvl4, *me)), lvl2), lvl1),
            4 => h(h(lvl2, h(h(*me, lvl4), lvl3)), lvl1),
            5 => h(h(lvl2, h(h(lvl4, *me), lvl3)), lvl1),
            6 => h(h(lvl2, h(lvl3, h(*me, lvl4))), lvl1),
            7 => h(h(lvl2, h(lvl3, h(lvl4, *me))), lvl1),
            8 => h(lvl1, h(h(h(*me, lvl4), lvl3), lvl2)),
            9 => h(lvl1, h(h(h(lvl4, *me), lvl3), lvl2)),
            10 => h(lvl1, h(h(lvl3, h(*me, lvl4)), lvl2)),
            11 => h(lvl1, h(h(lvl3, h(lvl4, *me)), lvl2)),
            12 => h(lvl1, h(lvl2, h(h(*me, lvl4), lvl3))),
            13 => h(lvl1, h(lvl2, h(h(lvl4, *me), lvl3))),
            14 => h(lvl1, h(lvl2, h(lvl3, h(*me, lvl4)))),
            15 => h(lvl1, h(lvl2, h(lvl3, h(lvl4, *me)))),
            _ => {
                return Err(TrieError::InvalidOperation(format!(
                    "Invalid nibble index: {}",
                    nibble_idx
                )))
            }
        };

        Ok(result)
    }

    pub fn to_json(&self) -> Vec<serde_json::Value> {
        self.steps
            .iter()
            .map(|step| serde_json::to_value(step).unwrap())
            .collect()
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let mut parts = vec![cbor::begin_list()];

        for step in &self.steps {
            match step {
                ProofStep::Branch { skip, neighbors } => {
                    let neighbors_bytes = hex::decode(neighbors).unwrap();
                    let part1 = &neighbors_bytes[..64];
                    let part2 = &neighbors_bytes[64..];

                    parts.push(cbor::tag(
                        121,
                        &cbor::sequence(&[
                            cbor::begin_list(),
                            cbor::int(*skip as i64),
                            cbor::sequence(&[
                                cbor::begin_bytes(),
                                cbor::bytes(part1),
                                cbor::bytes(part2),
                                cbor::end(),
                            ]),
                            cbor::end(),
                        ]),
                    ));
                }
                ProofStep::Fork { skip, neighbor } => {
                    parts.push(cbor::tag(
                        122,
                        &cbor::sequence(&[
                            cbor::begin_list(),
                            cbor::int(*skip as i64),
                            cbor::tag(
                                121,
                                &cbor::sequence(&[
                                    cbor::begin_list(),
                                    cbor::int(neighbor.nibble as i64),
                                    cbor::bytes(&hex::decode(&neighbor.prefix).unwrap()),
                                    cbor::bytes(&hex::decode(&neighbor.root).unwrap()),
                                    cbor::end(),
                                ]),
                            ),
                            cbor::end(),
                        ]),
                    ));
                }
                ProofStep::Leaf { skip, neighbor } => {
                    parts.push(cbor::tag(
                        123,
                        &cbor::sequence(&[
                            cbor::begin_list(),
                            cbor::int(*skip as i64),
                            cbor::bytes(&hex::decode(&neighbor.key).unwrap()),
                            cbor::bytes(&hex::decode(&neighbor.value).unwrap()),
                            cbor::end(),
                        ]),
                    ));
                }
            }
        }

        parts.push(cbor::end());
        cbor::sequence(&parts)
    }

    pub fn from_json(key: &[u8], value: Option<Vec<u8>>, steps: Vec<serde_json::Value>) -> Result<Self> {
        let path = into_path(key);
        let parsed_steps: Vec<ProofStep> = steps
            .into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect();

        Ok(Proof {
            path,
            value,
            steps: parsed_steps,
        })
    }
}

impl fmt::Display for Trie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "ø")
        } else {
            write!(f, "Trie(size: {})", self.size)
        }
    }
}
