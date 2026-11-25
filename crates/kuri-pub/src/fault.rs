//! Faults: what a depot refuses with, and how a client tells them apart.
//!
//! Kuri Link gives an application one fault, `App`, carrying a text message.
//! A depot's message is always `<code>: <detail>`: `code` is one of [`Code`],
//! snake_case and stable; `detail` is for people. A client matches on the
//! code, never on the prose.
//!
//! A refused `open` can only be a fault (Kuri Link accepts a stream in two
//! phases), which is why the code rides in the fault's message rather than in
//! a result union.

use std::fmt;

/// Why a depot refused a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Code {
    /// A kind, name, version, channel or digest breaks its rule.
    BadName,
    /// A manifest breaks a rule of its own.
    BadManifest,
    /// `get` asked to start past the end of the blob.
    BadRange,
    /// No such kind, name, version, channel or blob.
    NotFound,
    /// The version exists with other content. The detail names the stored
    /// manifest's digest.
    Conflict,
    /// `publish` named blobs the depot does not hold. A client calls `has`
    /// first; this is the fallback.
    MissingBlobs,
    /// The bytes of a `put` do not hash to the digest it named.
    DigestMismatch,
    /// A `put` sent more or fewer bytes than it said it would.
    SizeMismatch,
    /// `set_channel` expected a channel position it no longer has.
    ChannelMoved,
    /// Over a limit: a manifest, a blob, or a list of digests.
    TooLarge,
    /// A digest algorithm this depot does not know.
    UnsupportedAlg,
    /// The depot's own storage failed.
    Storage,
    /// A code this version of the contract does not know, as sent; empty when
    /// the message had no code at all.
    Unknown(String),
}

/// Every code this contract defines, for tests and documentation.
pub const CODES: [Code; 12] = [
    Code::BadName,
    Code::BadManifest,
    Code::BadRange,
    Code::NotFound,
    Code::Conflict,
    Code::MissingBlobs,
    Code::DigestMismatch,
    Code::SizeMismatch,
    Code::ChannelMoved,
    Code::TooLarge,
    Code::UnsupportedAlg,
    Code::Storage,
];

impl Code {
    /// The code as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Code::BadName => "bad_name",
            Code::BadManifest => "bad_manifest",
            Code::BadRange => "bad_range",
            Code::NotFound => "not_found",
            Code::Conflict => "conflict",
            Code::MissingBlobs => "missing_blobs",
            Code::DigestMismatch => "digest_mismatch",
            Code::SizeMismatch => "size_mismatch",
            Code::ChannelMoved => "channel_moved",
            Code::TooLarge => "too_large",
            Code::UnsupportedAlg => "unsupported_alg",
            Code::Storage => "storage",
            Code::Unknown(code) => code,
        }
    }

    /// The code named by `s`; [`Code::Unknown`] if this contract does not
    /// define it.
    pub fn parse(s: &str) -> Code {
        CODES
            .into_iter()
            .find(|code| code.as_str() == s)
            .unwrap_or_else(|| Code::Unknown(s.to_owned()))
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A depot's refusal: a code to match on and a detail for people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// What to match on.
    pub code: Code,
    /// For people; never parsed.
    pub detail: String,
}

impl Fault {
    /// A fault with `code` and `detail`.
    pub fn new(code: Code, detail: impl Into<String>) -> Fault {
        Fault {
            code,
            detail: detail.into(),
        }
    }

    /// Reads a fault from the message of a Kuri Link `App` fault.
    ///
    /// A message that does not start with a snake_case code and `": "` came
    /// from something other than a depot; it is returned whole as the detail,
    /// with an empty [`Code::Unknown`].
    pub fn parse(message: &str) -> Fault {
        match message.split_once(": ") {
            Some((code, detail)) if is_code(code) => Fault::new(Code::parse(code), detail),
            _ => Fault::new(Code::Unknown(String::new()), message),
        }
    }
}

/// `[a-z][a-z0-9_]*`: the shape every code has, so prose with a colon in it
/// is not mistaken for one.
fn is_code(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The message to put in a Kuri Link `App` fault.
impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Fault {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_round_trips_through_a_message() {
        for code in CODES {
            let fault = Fault::new(code.clone(), "some detail: with a colon");
            assert_eq!(Fault::parse(&fault.to_string()), fault);
        }
    }

    #[test]
    fn codes_are_distinct_snake_case() {
        let mut seen = std::collections::HashSet::new();
        for code in CODES {
            assert!(is_code(code.as_str()), "{code}");
            assert!(seen.insert(code.as_str().to_owned()), "{code} twice");
        }
    }

    #[test]
    fn a_code_from_a_newer_depot_is_kept() {
        let fault = Fault::parse("quota_exceeded: the home's share is full");
        assert_eq!(fault.code, Code::Unknown("quota_exceeded".into()));
        assert_eq!(fault.detail, "the home's share is full");
        assert_eq!(
            fault.to_string(),
            "quota_exceeded: the home's share is full"
        );
    }

    #[test]
    fn prose_is_not_taken_for_a_code() {
        for message in ["Connection reset: by peer", "timed out", "a b: c", ": x"] {
            let fault = Fault::parse(message);
            assert_eq!(fault.code, Code::Unknown(String::new()), "{message}");
            assert_eq!(fault.detail, message);
        }
    }
}
