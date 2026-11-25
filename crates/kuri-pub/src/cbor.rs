//! The CBOR subset a manifest is written in, and its one canonical encoding.
//!
//! A manifest's identity is the digest of its canonical encoding, unknown
//! keys included. Two implementations agree on that encoding only if every
//! value in the manifest has exactly one: so the subset has text map keys
//! only, no floats, no tags, no indefinite lengths, no duplicate keys, and of
//! the simple values only `false`, `true` and `null`.
//!
//! The canonical encoding is RFC 8949 §4.2.1: integers and lengths in their
//! shortest form, map keys sorted bytewise by their own encoding.

use std::collections::HashSet;

use ciborium::Value;
use ciborium::value::Integer;

/// Deepest nesting of arrays and maps. A manifest needs four; the limit
/// keeps a hostile one from exhausting the stack.
pub const MAX_DEPTH: usize = 32;

/// Why a value is outside the subset, or bytes are not CBOR.
pub type SubsetError = String;

/// Checks that `value` is inside the subset.
pub fn check(value: &Value) -> Result<(), SubsetError> {
    check_at(value, 0)
}

fn check_at(value: &Value, depth: usize) -> Result<(), SubsetError> {
    if depth > MAX_DEPTH {
        return Err(format!("nested deeper than {MAX_DEPTH}"));
    }
    match value {
        Value::Integer(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) | Value::Null => {
            Ok(())
        }
        Value::Float(_) => Err("a float; use an integer or text".into()),
        Value::Tag(tag, _) => Err(format!("tag {tag}; tags are not allowed")),
        Value::Array(items) => items.iter().try_for_each(|v| check_at(v, depth + 1)),
        Value::Map(entries) => {
            let mut keys = HashSet::new();
            for (k, v) in entries {
                let Value::Text(k) = k else {
                    return Err("a map key that is not text".into());
                };
                if !keys.insert(k.as_str()) {
                    return Err(format!("the key {k:?} twice in one map"));
                }
                check_at(v, depth + 1)?;
            }
            Ok(())
        }
        _ => Err("a value of a kind this subset does not have".into()),
    }
}

/// The canonical encoding of `value`, which must be inside the subset.
pub fn encode(value: &Value) -> Result<Vec<u8>, SubsetError> {
    check(value)?;
    let mut out = Vec::new();
    write(value, &mut out);
    Ok(out)
}

fn header(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend(n.to_be_bytes());
        }
    }
}

/// Writes a value already checked to be inside the subset.
fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Integer(i) => {
            let i = i128::from(*i);
            if i >= 0 {
                header(0, i as u64, out);
            } else {
                header(1, (-1 - i) as u64, out);
            }
        }
        Value::Bytes(b) => {
            header(2, b.len() as u64, out);
            out.extend(b);
        }
        Value::Text(t) => {
            header(3, t.len() as u64, out);
            out.extend(t.as_bytes());
        }
        Value::Array(items) => {
            header(4, items.len() as u64, out);
            items.iter().for_each(|v| write(v, out));
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, &Value)> = entries
                .iter()
                .map(|(k, v)| {
                    let mut key = Vec::new();
                    write(k, &mut key);
                    (key, v)
                })
                .collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            header(5, encoded.len() as u64, out);
            for (key, v) in encoded {
                out.extend(key);
                write(v, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        _ => unreachable!("checked to be inside the subset"),
    }
}

/// Reads one value inside the subset from `bytes`, which must hold exactly
/// that value. Any definite encoding is accepted (a longer integer than
/// needed, keys in any order); what is refused is anything the canonical
/// encoding could not reproduce.
pub fn decode(bytes: &[u8]) -> Result<Value, SubsetError> {
    let mut r = Reader { bytes, at: 0 };
    let value = r.value(0)?;
    if r.at != bytes.len() {
        return Err(format!("{} bytes after the value", bytes.len() - r.at));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: u64) -> Result<&[u8], SubsetError> {
        let end = usize::try_from(n)
            .ok()
            .and_then(|n| self.at.checked_add(n))
            .filter(|end| *end <= self.bytes.len())
            .ok_or("the bytes end inside a value")?;
        let s = &self.bytes[self.at..end];
        self.at = end;
        Ok(s)
    }

    /// The major type and its argument. Refuses an indefinite length.
    fn head(&mut self) -> Result<(u8, u8, u64), SubsetError> {
        let b = self.take(1)?[0];
        let (major, info) = (b >> 5, b & 0x1f);
        let n = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            31 => return Err("an indefinite length".into()),
            _ => return Err(format!("reserved additional information {info}")),
        };
        Ok((major, info, n))
    }

    fn value(&mut self, depth: usize) -> Result<Value, SubsetError> {
        if depth > MAX_DEPTH {
            return Err(format!("nested deeper than {MAX_DEPTH}"));
        }
        let (major, info, n) = self.head()?;
        Ok(match major {
            0 => Value::Integer(Integer::from(n)),
            1 => Value::Integer(Integer::try_from(-1 - i128::from(n)).expect("in CBOR's range")),
            2 => Value::Bytes(self.take(n)?.to_vec()),
            3 => Value::Text(
                String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "text that is not UTF-8")?,
            ),
            4 => {
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let mut entries = Vec::new();
                let mut keys = HashSet::new();
                for _ in 0..n {
                    let Value::Text(k) = self.value(depth + 1)? else {
                        return Err("a map key that is not text".into());
                    };
                    if !keys.insert(k.clone()) {
                        return Err(format!("the key {k:?} twice in one map"));
                    }
                    entries.push((Value::Text(k), self.value(depth + 1)?));
                }
                Value::Map(entries)
            }
            6 => return Err(format!("tag {n}; tags are not allowed")),
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                25..=27 => return Err("a float; use an integer or text".into()),
                _ => return Err(format!("the simple value {n}")),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn text(s: &str) -> Value {
        Value::Text(s.into())
    }

    #[test]
    fn integers_take_their_shortest_form() {
        for (n, expect) in [
            (0i128, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65_536, "1a00010000"),
            (4_294_967_296, "1b0000000100000000"),
            (-1, "20"),
            (-25, "3818"),
            (u64::MAX as i128, "1bffffffffffffffff"),
            (-1 - u64::MAX as i128, "3bffffffffffffffff"),
        ] {
            let v = Value::Integer(Integer::try_from(n).unwrap());
            assert_eq!(encode(&v).unwrap(), hex(expect), "{n}");
            assert_eq!(decode(&hex(expect)).unwrap(), v, "{n}");
        }
    }

    #[test]
    fn map_keys_sort_by_their_encoding() {
        // Bytewise over the encoded key puts the shorter key first: "b"
        // before "aa", unlike plain string order.
        let v = Value::Map(vec![(text("aa"), Value::Null), (text("b"), Value::Null)]);
        assert_eq!(encode(&v).unwrap(), hex("a26162f6626161f6"));
    }

    #[test]
    fn a_longer_encoding_reads_as_the_same_value() {
        // 1 written in eight bytes; keys out of order.
        let long = hex("a26162f66161 1b0000000000000001".replace(' ', "").as_str());
        let v = decode(&long).unwrap();
        assert_eq!(
            encode(&v).unwrap(),
            hex("a2616101 6162f6".replace(' ', "").as_str())
        );
    }

    #[test]
    fn indefinite_lengths_are_refused() {
        for bytes in ["9f01ff", "bf6161f6ff", "7f6161ff", "5f4101ff"] {
            let err = decode(&hex(bytes)).unwrap_err();
            assert!(err.contains("indefinite"), "{bytes}: {err}");
        }
    }

    #[test]
    fn tags_are_refused() {
        // tag 1 (epoch time) on an integer.
        assert!(decode(&hex("c11a5f000000")).unwrap_err().contains("tag"));
        let v = Value::Tag(1, Box::new(Value::Integer(1.into())));
        assert!(encode(&v).unwrap_err().contains("tag"));
    }

    #[test]
    fn floats_are_refused() {
        for bytes in ["f93c00", "fa3f800000", "fb3ff0000000000000"] {
            assert!(
                decode(&hex(bytes)).unwrap_err().contains("float"),
                "{bytes}"
            );
        }
        assert!(encode(&Value::Float(1.0)).unwrap_err().contains("float"));
    }

    #[test]
    fn other_simple_values_are_refused() {
        for bytes in ["f7", "f0", "f818"] {
            assert!(
                decode(&hex(bytes)).unwrap_err().contains("simple"),
                "{bytes}"
            );
        }
    }

    #[test]
    fn map_keys_must_be_text() {
        assert!(decode(&hex("a101f6")).unwrap_err().contains("not text"));
        let v = Value::Map(vec![(Value::Integer(1.into()), Value::Null)]);
        assert!(encode(&v).unwrap_err().contains("not text"));
    }

    #[test]
    fn duplicate_keys_are_refused() {
        assert!(
            decode(&hex("a26161f66161f5"))
                .unwrap_err()
                .contains("twice")
        );
        let v = Value::Map(vec![(text("a"), Value::Null), (text("a"), Value::Null)]);
        assert!(encode(&v).unwrap_err().contains("twice"));
    }

    #[test]
    fn nesting_is_bounded() {
        let deep = |n: usize| {
            let mut bytes = vec![0x81; n];
            bytes.push(0x00);
            bytes
        };
        decode(&deep(MAX_DEPTH)).unwrap();
        assert!(decode(&deep(MAX_DEPTH + 1)).unwrap_err().contains("deeper"));
        let mut v = Value::Integer(0.into());
        for _ in 0..=MAX_DEPTH {
            v = Value::Array(vec![v]);
        }
        assert!(encode(&v).unwrap_err().contains("deeper"));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        assert!(decode(&hex("0000")).unwrap_err().contains("after"));
    }

    #[test]
    fn truncated_and_malformed_input_is_refused() {
        for bytes in [
            "",
            "18",
            "62 61".replace(' ', "").as_str(),
            "82 00".replace(' ', "").as_str(),
            "1c",
            "6261ff",
        ] {
            decode(&hex(bytes)).unwrap_err();
        }
        // A length far past the end must fail, not allocate.
        decode(&hex("5bffffffffffffffff00")).unwrap_err();
        decode(&hex("9bffffffffffffffff00")).unwrap_err();
    }
}
