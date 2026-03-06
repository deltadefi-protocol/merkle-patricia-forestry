/// CBOR encoding for proofs
/// Implements a subset of CBOR encoding needed for Merkle Patricia Forestry proofs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CborError {
    #[error("Cannot encode integer values larger than {0}")]
    IntegerTooLarge(u64),
}

/// Major type tokens
const TOKEN_BEGIN: u8 = 31;
const TOKEN_END: u8 = 255;

/// Concatenate encoded values from left to right
pub fn sequence(args: &[Vec<u8>]) -> Vec<u8> {
    args.concat()
}

/// Encode an integer value (signed)
pub fn int(val: i64) -> Vec<u8> {
    if val >= 0 {
        let (size, rest) = unsigned(val as u64);
        major_type(0, size, &rest, &[])
    } else {
        let (size, rest) = unsigned((-val - 1) as u64);
        major_type(1, size, &rest, &[])
    }
}

/// Encode a definite byte buffer
pub fn bytes(val: &[u8]) -> Vec<u8> {
    let (size, rest) = unsigned(val.len() as u64);
    major_type(2, size, &rest, &[val])
}

/// Begin encoding an indefinite byte buffer
pub fn begin_bytes() -> Vec<u8> {
    major_type(2, TOKEN_BEGIN, &[], &[])
}

/// Encode a UTF-8 text string
pub fn text(val: &str) -> Vec<u8> {
    let buffer = val.as_bytes();
    let (size, rest) = unsigned(buffer.len() as u64);
    major_type(3, size, &rest, &[buffer])
}

/// Begin encoding an indefinite text string
pub fn begin_text() -> Vec<u8> {
    major_type(3, TOKEN_BEGIN, &[], &[])
}

/// Encode a uniform finite list of elements
pub fn list<T, F>(encode_elem: F, xs: &[T]) -> Vec<u8>
where
    F: Fn(&T) -> Vec<u8>,
{
    let (size, rest) = unsigned(xs.len() as u64);
    let encoded: Vec<Vec<u8>> = xs.iter().map(|x| encode_elem(x)).collect();
    let mut buffers = vec![&rest as &[u8]];
    for e in &encoded {
        buffers.push(e);
    }
    major_type(4, size, &[], &buffers)
}

/// Encode a heterogeneous finite array of elements
pub fn array(xs: &[Vec<u8>]) -> Vec<u8> {
    let (size, rest) = unsigned(xs.len() as u64);
    let buffers: Vec<&[u8]> = std::iter::once(rest.as_slice())
        .chain(xs.iter().map(|x| x.as_slice()))
        .collect();
    major_type(4, size, &[], &buffers)
}

/// Encode the beginning of an indefinite list or array
pub fn begin_list() -> Vec<u8> {
    major_type(4, TOKEN_BEGIN, &[], &[])
}

/// Encode a uniform key:value definite map
pub fn map<K, V, FK, FV>(
    encode_key: FK,
    encode_value: FV,
    obj: &[(K, V)],
) -> Vec<u8>
where
    FK: Fn(&K) -> Vec<u8>,
    FV: Fn(&V) -> Vec<u8>,
{
    let (size, rest) = unsigned(obj.len() as u64);
    let mut encoded = Vec::new();
    for (k, v) in obj {
        encoded.push(encode_key(k));
        encoded.push(encode_value(v));
    }
    let buffers: Vec<&[u8]> = std::iter::once(rest.as_slice())
        .chain(encoded.iter().map(|x| x.as_slice()))
        .collect();
    major_type(5, size, &[], &buffers)
}

/// Encode the beginning of an indefinite map
pub fn begin_map() -> Vec<u8> {
    major_type(5, TOKEN_BEGIN, &[], &[])
}

/// Encode a tagged value
pub fn tag(t: u64, val: &[u8]) -> Vec<u8> {
    let (size, rest) = unsigned(t);
    major_type(6, size, &rest, &[val])
}

/// Encode the end of any indefinite stream
pub fn end() -> Vec<u8> {
    vec![TOKEN_END]
}

// Helper functions

fn unsigned(val: u64) -> (u8, Vec<u8>) {
    if val < 24 {
        (val as u8, vec![])
    } else if val < 256 {
        (24, vec![val as u8])
    } else if val < 65536 {
        (25, (val as u16).to_be_bytes().to_vec())
    } else if val < 4294967296 {
        (26, (val as u32).to_be_bytes().to_vec())
    } else {
        (27, val.to_be_bytes().to_vec())
    }
}

fn major_type(i: u8, val: u8, rest: &[u8], args: &[&[u8]]) -> Vec<u8> {
    let mut result = vec![i << 5 | val];
    result.extend_from_slice(rest);
    for arg in args {
        result.extend_from_slice(arg);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same_bytes(got: Vec<u8>, expected: &str) {
        assert_eq!(hex::encode(got), expected);
    }

    #[test]
    fn test_int() {
        same_bytes(int(0), "00");
        same_bytes(int(1), "01");
        same_bytes(int(10), "0a");
        same_bytes(int(23), "17");
        same_bytes(int(24), "1818");
        same_bytes(int(25), "1819");
        same_bytes(int(100), "1864");
        same_bytes(int(1000), "1903e8");
        same_bytes(int(1000000), "1a000f4240");
        same_bytes(int(1000000000000), "1b000000e8d4a51000");
        same_bytes(int(9007199254740991), "1b001fffffffffffff");
        same_bytes(int(-1), "20");
        same_bytes(int(-10), "29");
        same_bytes(int(-100), "3863");
        same_bytes(int(-1000), "3903e7");
    }

    #[test]
    fn test_int_edge_cases() {
        // Test int(25) - boundary between different encodings
        same_bytes(int(25), "1819");

        // Test large integers
        same_bytes(int(1000000000000), "1b000000e8d4a51000");
        same_bytes(int(9007199254740991), "1b001fffffffffffff");

        // Note: JavaScript test throws RangeError for 18446744073709551615 (u64::MAX)
        // Rust uses i64, so i64::MAX is the limit (9223372036854775807)
        // Values beyond i64::MAX cannot be represented in i64
    }

    #[test]
    fn test_bytes() {
        same_bytes(bytes(&[]), "40");
        same_bytes(bytes(&hex::decode("01020304").unwrap()), "4401020304");
    }

    #[test]
    fn test_begin_bytes() {
        let result = sequence(&[
            begin_bytes(),
            bytes(&hex::decode("0102").unwrap()),
            bytes(&hex::decode("030405").unwrap()),
            end(),
        ]);
        same_bytes(result, "5f42010243030405ff");
    }

    #[test]
    fn test_text() {
        same_bytes(text(""), "60");
        same_bytes(text("a"), "6161");
        same_bytes(text("IETF"), "6449455446");
        same_bytes(text("'\\"), "62275c");
        same_bytes(text("ü"), "62c3bc");
        same_bytes(text("水"), "63e6b0b4");
    }

    #[test]
    fn test_text_utf16_surrogate_pair() {
        // JavaScript test: '\ud800\udd51' -> '64f0908591'
        // This is a UTF-16 surrogate pair representing U+10151
        // In Rust, we use the actual Unicode code point U+10151
        // UTF-8 encoding of U+10151 is: f0 90 85 91
        let character = char::from_u32(0x10151).unwrap();
        same_bytes(text(&character.to_string()), "64f0908591");
    }

    #[test]
    fn test_begin_text() {
        let result = sequence(&[
            begin_text(),
            text("strea"),
            text("ming"),
            end(),
        ]);
        same_bytes(result, "7f657374726561646d696e67ff");
    }

    #[test]
    fn test_list() {
        same_bytes(list(|&x| int(x), &[]), "80");
        same_bytes(list(|&x| int(x), &[1i64, 2, 3]), "83010203");

        // Test 25-element list (from JS tests)
        let vec = vec![1i64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25];
        same_bytes(
            list(|&x| int(x), &vec),
            "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
        );
    }

    #[test]
    fn test_array() {
        let arr = vec![
            int(1),
            list(|&x| int(x), &[2i64, 3]),
            list(|&x| int(x), &[4i64, 5]),
        ];
        same_bytes(array(&arr), "8301820203820405");
    }

    #[test]
    fn test_begin_list() {
        // Empty indefinite list
        let result = sequence(&[begin_list(), end()]);
        same_bytes(result, "9fff");

        // Indefinite list with nested indefinite list
        let result = sequence(&[
            begin_list(),
            int(1),
            list(|&x| int(x), &[2i64, 3]),
            sequence(&[begin_list(), int(4), int(5), end()]),
            end(),
        ]);
        same_bytes(result, "9f018202039f0405ffff");

        // Indefinite list with definite arrays: [1, [2, 3], [4, 5]]
        let result = sequence(&[
            begin_list(),
            int(1),
            list(|&x| int(x), &[2i64, 3]),
            list(|&x| int(x), &[4i64, 5]),
            end(),
        ]);
        same_bytes(result, "9f01820203820405ff");

        // Array with indefinite list: [1, [2, 3], indefinite[4, 5]]
        let arr = vec![
            int(1),
            list(|&x| int(x), &[2i64, 3]),
            sequence(&[begin_list(), int(4), int(5), end()]),
        ];
        same_bytes(array(&arr), "83018202039f0405ff");

        // Array with indefinite list in middle: [1, indefinite[2, 3], [4, 5]]
        let arr = vec![
            int(1),
            sequence(&[begin_list(), int(2), int(3), end()]),
            list(|&x| int(x), &[4i64, 5]),
        ];
        same_bytes(array(&arr), "83019f0203ff820405");

        // Indefinite list with 25 elements
        let mut parts = vec![begin_list()];
        for i in 1..=25 {
            parts.push(int(i));
        }
        parts.push(end());
        same_bytes(
            sequence(&parts),
            "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
        );
    }

    #[test]
    fn test_map() {
        // Empty map
        let empty: Vec<(i64, i64)> = vec![];
        same_bytes(map(|&x| int(x), |&x| int(x), &empty), "a0");

        // Simple int map
        let m = vec![(1i64, 2i64), (3, 4)];
        same_bytes(map(|&x| int(x), |&x| int(x), &m), "a201020304");
    }

    #[test]
    fn test_map_text_keys_mixed_values() {
        // Map with text keys and mixed values (from JS test)
        // { a: int(1), b: list(int, [2, 3]) } -> 'a26161016162820203'
        let m = vec![
            ("a", int(1)),
            ("b", list(|&x| int(x), &[2i64, 3])),
        ];
        same_bytes(
            map(|&x| text(x), |x| x.clone(), &m),
            "a26161016162820203",
        );
    }

    #[test]
    fn test_array_with_text_and_map() {
        // Array containing text and map: ['a', { b: 'c' }] -> '826161a161626163'
        let arr = vec![
            text("a"),
            map(|&x| text(x), |&x| text(x), &[("b", "c")]),
        ];
        same_bytes(array(&arr), "826161a161626163");
    }

    #[test]
    fn test_map_five_elements() {
        // Map with 5 text key-value pairs (from JS test)
        let m = vec![
            ("a", "A"),
            ("b", "B"),
            ("c", "C"),
            ("d", "D"),
            ("e", "E"),
        ];
        same_bytes(
            map(|&x| text(x), |&x| text(x), &m),
            "a56161614161626142616361436164614461656145",
        );
    }

    #[test]
    fn test_begin_map() {
        // Indefinite map with indefinite list value (from JS test)
        // { a: 1, b: indefinite[2, 3] } -> 'bf61610161629f0203ffff'
        let result = sequence(&[
            begin_map(),
            text("a"),
            int(1),
            text("b"),
            sequence(&[begin_list(), int(2), int(3), end()]),
            end(),
        ]);
        same_bytes(result, "bf61610161629f0203ffff");

        // Array with indefinite map inside: ['a', indefinite{ b: 'c' }] -> '826161bf61626163ff'
        let arr = vec![
            text("a"),
            sequence(&[begin_map(), text("b"), text("c"), end()]),
        ];
        same_bytes(array(&arr), "826161bf61626163ff");
    }

    #[test]
    fn test_tag() {
        same_bytes(tag(1, &int(1363896240)), "c11a514b67b0");
        same_bytes(
            tag(23, &bytes(&hex::decode("01020304").unwrap())),
            "d74401020304",
        );
        same_bytes(
            tag(24, &bytes(&hex::decode("6449455446").unwrap())),
            "d818456449455446",
        );
        same_bytes(
            tag(32, &text("http://www.example.com")),
            "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
        );
    }
}
