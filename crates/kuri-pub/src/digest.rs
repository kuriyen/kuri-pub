//! Content digests: what blobs and manifests are named by.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::fault::{Code, Fault};

/// A digest algorithm.
///
/// `alg` is a field, checked by value, and a store keeps each algorithm's
/// blobs apart, so a second algorithm is an addition. The one reserved is
/// Fuchsia's Merkle root, a SHA-256 tree over 8 KiB chunks, which lets a
/// download be verified chunk by chunk as it arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Alg {
    /// SHA-256 over the whole content.
    Sha256,
}

impl Alg {
    /// The name on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::Sha256 => "sha256",
        }
    }

    /// The algorithm named `s`; a name this contract does not define is
    /// `unsupported_alg`, never ignored.
    pub fn parse(s: &str) -> Result<Alg, Fault> {
        match s {
            "sha256" => Ok(Alg::Sha256),
            _ => Err(Fault::new(
                Code::UnsupportedAlg,
                format!("digest algorithm {s:?}"),
            )),
        }
    }

    /// Length of a digest's `hex`.
    pub fn hex_len(self) -> usize {
        match self {
            Alg::Sha256 => 64,
        }
    }
}

/// A digest: `{alg, hex}` on the wire, exactly those two keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Wire", into = "Wire")]
pub struct Digest {
    alg: Alg,
    hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    alg: String,
    hex: String,
}

impl Digest {
    /// Checks a digest's parts. An unknown `alg` is `unsupported_alg`; a
    /// `hex` of the wrong length or not lowercase hexadecimal is `bad_name`.
    pub fn new(alg: &str, hex: impl Into<String>) -> Result<Digest, Fault> {
        let alg = Alg::parse(alg)?;
        let hex = hex.into();
        if hex.len() != alg.hex_len() {
            return Err(Fault::new(
                Code::BadName,
                format!(
                    "{} digest {hex:?} is not {} characters",
                    alg.as_str(),
                    alg.hex_len()
                ),
            ));
        }
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Fault::new(
                Code::BadName,
                format!("digest {hex:?} is not lowercase hexadecimal"),
            ));
        }
        Ok(Digest { alg, hex })
    }

    /// The SHA-256 digest of `bytes`.
    pub fn sha256(bytes: &[u8]) -> Digest {
        Digest::from_sha256(Sha256::digest(bytes).into())
    }

    /// A SHA-256 digest from its 32 bytes, as a streaming hasher ends with.
    pub fn from_sha256(bytes: [u8; 32]) -> Digest {
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Digest {
            alg: Alg::Sha256,
            hex,
        }
    }

    /// The algorithm.
    pub fn alg(&self) -> Alg {
        self.alg
    }

    /// The digest in lowercase hexadecimal.
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl TryFrom<Wire> for Digest {
    type Error = Fault;
    fn try_from(w: Wire) -> Result<Digest, Fault> {
        Digest::new(&w.alg, w.hex)
    }
}

impl From<Digest> for Wire {
    fn from(d: Digest) -> Wire {
        Wire {
            alg: d.alg.as_str().into(),
            hex: d.hex,
        }
    }
}

/// A digest as a depot reports it in a reply, read without checking.
///
/// A reply is read as the depot wrote it, so that a depot that has learnt a
/// second algorithm still answers a client that has not: the client reads
/// the whole page, and checks a digest with [`ReportedDigest::known`] only
/// when it is about to use it. A request carries a [`Digest`], which the
/// depot checks as it reads.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReportedDigest {
    /// The algorithm, as the depot named it.
    pub alg: String,
    /// The digest, as the depot wrote it.
    pub hex: String,
}

impl ReportedDigest {
    /// The digest, if this client knows its algorithm and the form is right.
    pub fn known(&self) -> Result<Digest, Fault> {
        Digest::new(&self.alg, self.hex.clone())
    }
}

impl From<Digest> for ReportedDigest {
    fn from(d: Digest) -> ReportedDigest {
        ReportedDigest {
            alg: d.alg.as_str().into(),
            hex: d.hex,
        }
    }
}

/// `sha256:<hex>`, as a fault's detail names a digest.
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.alg.as_str(), self.hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_of_known_input() {
        assert_eq!(Digest::sha256(b"").hex(), EMPTY);
        assert_eq!(
            Digest::sha256(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn an_unknown_algorithm_is_refused_not_ignored() {
        let err = Digest::new("blake3", EMPTY).unwrap_err();
        assert_eq!(err.code, Code::UnsupportedAlg);
        assert_eq!(
            Digest::new("SHA256", EMPTY).unwrap_err().code,
            Code::UnsupportedAlg
        );
    }

    #[test]
    fn hex_must_have_the_algorithm_s_length() {
        assert_eq!(
            Digest::new("sha256", &EMPTY[1..]).unwrap_err().code,
            Code::BadName
        );
        assert_eq!(
            Digest::new("sha256", format!("{EMPTY}0")).unwrap_err().code,
            Code::BadName
        );
    }

    #[test]
    fn hex_must_be_lowercase() {
        let upper = EMPTY.to_uppercase();
        assert_eq!(
            Digest::new("sha256", upper).unwrap_err().code,
            Code::BadName
        );
        let not_hex = format!("g{}", &EMPTY[1..]);
        assert_eq!(
            Digest::new("sha256", not_hex).unwrap_err().code,
            Code::BadName
        );
    }

    #[test]
    fn wire_form_is_exactly_alg_and_hex() {
        let d = Digest::sha256(b"");
        let v = Value::serialized(&d).unwrap();
        assert_eq!(
            v,
            Value::Map(vec![
                (Value::Text("alg".into()), Value::Text("sha256".into())),
                (Value::Text("hex".into()), Value::Text(EMPTY.into())),
            ])
        );
        assert_eq!(v.deserialized::<Digest>().unwrap(), d);
        let extra = Value::Map(vec![
            (Value::Text("alg".into()), Value::Text("sha256".into())),
            (Value::Text("hex".into()), Value::Text(EMPTY.into())),
            (Value::Text("size".into()), Value::Integer(0.into())),
        ]);
        extra.deserialized::<Digest>().unwrap_err();
        let unknown = Value::Map(vec![
            (Value::Text("alg".into()), Value::Text("md5".into())),
            (Value::Text("hex".into()), Value::Text(EMPTY.into())),
        ]);
        let err = unknown.deserialized::<Digest>().unwrap_err().to_string();
        assert!(err.contains("unsupported_alg"), "{err}");
    }
}
