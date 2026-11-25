//! The methods of app `pub`: their names, arguments and results.
//!
//! Every type here is what travels in a Kuri Link call or stream, through
//! serde. Kinds, names, versions, channels and digests check their rules as
//! they are read, so a request that deserializes is one whose names are valid.
//!
//! Read and write can be granted apart without touching this contract: Kuri
//! Link asks its authorizer about each request with the method's name. A
//! read-only grant is [`READ_METHODS`].

use std::collections::BTreeMap;

use ciborium::Value;
use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::fault::{Code, Fault};
use crate::names::{Channel, Kind, Name, Version};

/// The Kuri Link app a depot serves.
pub const APP: &str = "pub";

/// `call`: the kinds a depot holds.
pub const KINDS: &str = "kinds";
/// `call`: the names of a kind, a page at a time.
pub const LIST: &str = "list";
/// `call`: the versions of a name, a page at a time.
pub const VERSIONS: &str = "versions";
/// `call`: one version's manifest, by version or by channel.
pub const MANIFEST: &str = "manifest";
/// `call`: which blobs a depot holds.
pub const HAS: &str = "has";
/// `call`: records a version.
pub const PUBLISH: &str = "publish";
/// `call`: moves a channel.
pub const SET_CHANNEL: &str = "set_channel";
/// `open`: streams a blob down.
pub const GET: &str = "get";
/// `open`: streams a blob up.
pub const PUT: &str = "put";

/// The methods that change nothing.
pub const READ_METHODS: [&str; 6] = [KINDS, LIST, VERSIONS, MANIFEST, HAS, GET];

/// Page size when a request names none.
pub const DEFAULT_LIMIT: u32 = 100;
/// Largest page a depot returns, whatever was asked.
pub const MAX_LIMIT: u32 = 1000;
/// Most digests in one `has`.
pub const MAX_HAS: usize = 1024;
/// A depot's default cap on one blob, in bytes (64 GiB).
pub const DEFAULT_MAX_BLOB: u64 = 64 << 30;
/// The buffer a depot streams a `put` through, so its memory does not depend
/// on a blob's size.
pub const PUT_BUFFER: usize = 64 * 1024;

/// The page size a depot serves for `limit`.
pub fn page_size(limit: Option<u32>) -> usize {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize
}

/// Arguments that are an empty map, as `kinds` takes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

/// One kind in the reply to `kinds`, which lists them in bytewise order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindCount {
    /// The kind.
    pub kind: Kind,
    /// How many names it has.
    pub names: u64,
}

/// Arguments of `list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListArgs {
    /// Which kind.
    pub kind: Kind,
    /// Start after this name; the previous page's `next`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Name>,
    /// Page size; see [`page_size`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Where a channel points, and how many times it has moved.
///
/// `seq` starts at 1 and grows on every move, a rollback included. A client
/// refuses a reply whose `seq` is below one it has already seen for that
/// channel: that reply is stale, not a rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelPointer {
    /// The version it points at.
    pub version: Version,
    /// Its position.
    pub seq: u64,
}

/// One name in a page of `list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListItem {
    /// The name.
    pub name: Name,
    /// How many versions it has.
    pub versions: u64,
    /// Its channels.
    pub channels: BTreeMap<Channel, ChannelPointer>,
}

/// A page of `list`, in bytewise order of the names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListPage {
    /// The names.
    pub items: Vec<ListItem>,
    /// Pass as `after` for the next page; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<Name>,
}

/// Arguments of `versions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionsArgs {
    /// Which kind.
    pub kind: Kind,
    /// Which name.
    pub name: Name,
    /// Start after this version; the previous page's `next`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Version>,
    /// Page size; see [`page_size`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One version in a page of `versions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionItem {
    /// The version.
    pub version: Version,
    /// Its manifest's digest.
    pub manifest: Digest,
    /// When the depot recorded it, in milliseconds since the Unix epoch.
    pub published: u64,
}

/// A page of `versions`, in the order they were published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionsPage {
    /// The versions.
    pub items: Vec<VersionItem>,
    /// Pass as `after` for the next page; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<Version>,
}

/// Arguments of `manifest`: a version, or a channel, not both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArgs {
    /// Which kind.
    pub kind: Kind,
    /// Which name.
    pub name: Name,
    /// This version…
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
    /// …or the one this channel points at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Channel>,
}

/// What `manifest` asks for, once checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum At<'a> {
    /// A version.
    Version(&'a Version),
    /// A channel's version.
    Channel(&'a Channel),
}

impl ManifestArgs {
    /// The version or channel asked for. Both or neither is `bad_name`.
    pub fn at(&self) -> Result<At<'_>, Fault> {
        match (&self.version, &self.channel) {
            (Some(v), None) => Ok(At::Version(v)),
            (None, Some(c)) => Ok(At::Channel(c)),
            _ => Err(Fault::new(
                Code::BadName,
                "manifest takes a version or a channel, not both or neither",
            )),
        }
    }
}

/// The reply to `manifest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestReply {
    /// The version.
    pub version: Version,
    /// The manifest's digest.
    pub digest: Digest,
    /// The manifest, as stored.
    pub manifest: Value,
    /// The channel's position, when asked by channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// Arguments of `has`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasArgs {
    /// At most [`MAX_HAS`]. The reply is one `bool` for each, in order.
    pub digests: Vec<Digest>,
}

impl HasArgs {
    /// Refuses more than [`MAX_HAS`] digests with `too_large`.
    pub fn check(&self) -> Result<(), Fault> {
        if self.digests.len() > MAX_HAS {
            return Err(Fault::new(
                Code::TooLarge,
                format!("{} digests, over {MAX_HAS}", self.digests.len()),
            ));
        }
        Ok(())
    }
}

/// Arguments of `publish`. The manifest is checked with
/// [`crate::Manifest::from_value`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishArgs {
    /// The manifest.
    pub manifest: Value,
}

/// The reply to `publish`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishReply {
    /// The manifest's digest.
    pub digest: Digest,
    /// `false` when this exact manifest was already the version.
    pub created: bool,
}

/// The fault `publish` returns when the version exists with other content.
/// Its detail names the stored manifest, so a client can tell a retry it got
/// wrong from a real conflict.
pub fn conflict(stored: &Digest) -> Fault {
    Fault::new(Code::Conflict, format!("stored {stored}"))
}

/// Arguments of `set_channel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetChannelArgs {
    /// Which kind.
    pub kind: Kind,
    /// Which name.
    pub name: Name,
    /// Which channel.
    pub channel: Channel,
    /// The version it is to point at; it must exist.
    pub version: Version,
    /// The `seq` the caller last saw, `0` if the channel did not exist. When
    /// given and not the channel's current `seq`, the move is refused with
    /// `channel_moved`. A position rather than a version: A→B→A would pass a
    /// version check although the channel moved twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<u64>,
}

/// The reply to `set_channel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetChannelReply {
    /// Where the channel pointed before, if it existed.
    pub previous: Option<Version>,
    /// Its new position.
    pub seq: u64,
}

/// Arguments of `get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetArgs {
    /// Which blob.
    pub digest: Digest,
    /// Start here, to resume; past the end is `bad_range`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// Arguments of `put`. The client then sends exactly `size` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutArgs {
    /// What the bytes must hash to.
    pub digest: Digest,
    /// How many bytes follow.
    pub size: u64,
}

/// A fault carried inside a stream, where Kuri Link has no fault to give.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultBody {
    /// The code, as [`Code::as_str`] spells it.
    pub code: String,
    /// For people.
    pub detail: String,
}

/// The one result a depot sends at the end of a `put`, or as soon as it
/// knows the blob is already there. A client reads it before treating a
/// failed write as the outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PutResult {
    /// Stored now (`true`), or already there (`false`).
    Stored {
        /// Whether this `put` stored it.
        stored: bool,
    },
    /// Refused after the stream began.
    Error {
        /// Why.
        error: FaultBody,
    },
}

impl From<Fault> for PutResult {
    fn from(f: Fault) -> PutResult {
        PutResult::Error {
            error: FaultBody {
                code: f.code.as_str().to_owned(),
                detail: f.detail,
            },
        }
    }
}

impl PutResult {
    /// `Ok(stored)`, or the fault.
    pub fn into_result(self) -> Result<bool, Fault> {
        match self {
            PutResult::Stored { stored } => Ok(stored),
            PutResult::Error { error } => Err(Fault::new(Code::parse(&error.code), error.detail)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(t: &T) {
        let v = Value::serialized(t).unwrap();
        assert_eq!(&v.deserialized::<T>().unwrap(), t);
    }

    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(k, v)| (Value::Text((*k).into()), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn page_size_defaults_and_caps() {
        assert_eq!(page_size(None), 100);
        assert_eq!(page_size(Some(5)), 5);
        assert_eq!(page_size(Some(5000)), 1000);
        assert_eq!(page_size(Some(0)), 1);
    }

    #[test]
    fn optional_arguments_are_left_out_not_null() {
        let args = ListArgs {
            kind: Kind::new("mod.bg3").unwrap(),
            after: None,
            limit: None,
        };
        assert_eq!(
            Value::serialized(&args).unwrap(),
            map(&[("kind", Value::Text("mod.bg3".into()))])
        );
        round_trip(&args);
    }

    #[test]
    fn arguments_with_a_bad_name_do_not_deserialize() {
        let v = map(&[
            ("kind", Value::Text("app".into())),
            ("after", Value::Text("CON".into())),
        ]);
        v.deserialized::<ListArgs>().unwrap_err();
    }

    #[test]
    fn manifest_takes_a_version_or_a_channel() {
        let mut args = ManifestArgs {
            kind: Kind::new("app").unwrap(),
            name: Name::new("x").unwrap(),
            version: Some(Version::new("1").unwrap()),
            channel: None,
        };
        assert!(matches!(args.at(), Ok(At::Version(_))));
        args.channel = Some(Channel::new("stable").unwrap());
        assert_eq!(args.at().unwrap_err().code, Code::BadName);
        args.version = None;
        assert!(matches!(args.at(), Ok(At::Channel(_))));
        args.channel = None;
        assert_eq!(args.at().unwrap_err().code, Code::BadName);
    }

    #[test]
    fn has_is_capped() {
        let d = Digest::sha256(b"");
        HasArgs {
            digests: vec![d.clone(); MAX_HAS],
        }
        .check()
        .unwrap();
        let err = HasArgs {
            digests: vec![d; MAX_HAS + 1],
        }
        .check()
        .unwrap_err();
        assert_eq!(err.code, Code::TooLarge);
    }

    #[test]
    fn conflict_names_the_stored_manifest() {
        let d = Digest::sha256(b"x");
        let f = Fault::parse(&conflict(&d).to_string());
        assert_eq!(f.code, Code::Conflict);
        assert_eq!(f.detail, format!("stored sha256:{}", d.hex()));
    }

    #[test]
    fn set_channel_round_trips_with_and_without_expect() {
        let mut args = SetChannelArgs {
            kind: Kind::new("app").unwrap(),
            name: Name::new("x").unwrap(),
            channel: Channel::new("stable").unwrap(),
            version: Version::new("2").unwrap(),
            expect: Some(0),
        };
        round_trip(&args);
        args.expect = None;
        round_trip(&args);
        round_trip(&SetChannelReply {
            previous: None,
            seq: 1,
        });
        round_trip(&SetChannelReply {
            previous: Some(Version::new("1").unwrap()),
            seq: 7,
        });
    }

    #[test]
    fn list_pages_carry_channel_positions() {
        let page = ListPage {
            items: vec![ListItem {
                name: Name::new("x").unwrap(),
                versions: 2,
                channels: BTreeMap::from([(
                    Channel::new("stable").unwrap(),
                    ChannelPointer {
                        version: Version::new("1").unwrap(),
                        seq: 3,
                    },
                )]),
            }],
            next: None,
        };
        round_trip(&page);
    }

    #[test]
    fn put_result_wire_forms() {
        let stored = PutResult::Stored { stored: false };
        assert_eq!(
            Value::serialized(&stored).unwrap(),
            map(&[("stored", Value::Bool(false))])
        );
        round_trip(&stored);
        let failed = PutResult::from(Fault::new(Code::DigestMismatch, "got sha256:00"));
        round_trip(&failed);
        let fault = failed.into_result().unwrap_err();
        assert_eq!(fault.code, Code::DigestMismatch);
        assert!(stored.into_result().is_ok());
    }

    #[test]
    fn read_methods_are_the_ones_that_change_nothing() {
        for m in [PUBLISH, SET_CHANNEL, PUT] {
            assert!(!READ_METHODS.contains(&m));
        }
    }
}
