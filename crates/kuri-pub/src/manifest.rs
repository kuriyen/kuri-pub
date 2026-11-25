//! Manifests: what one version of a thing is made of.
//!
//! A manifest is a CBOR map with text keys. A reader ignores keys it does not
//! know, and the depot keeps them, at every depth: an older depot must not
//! strip what a newer front end wrote. So a [`Manifest`] holds the whole value
//! as received, alongside the fields this contract reads from it.
//!
//! Its identity is the digest of its canonical encoding ([`crate::cbor`]),
//! unknown keys included. That canonical form is what a depot stores. A
//! retried publish must send the same manifest: a new `created` is a new
//! manifest.

use std::collections::BTreeMap;

use ciborium::Value;

use crate::cbor;
use crate::digest::Digest;
use crate::fault::{Code, Fault};
use crate::names::{Kind, Name, Version, check_path, check_paths_together};

/// The manifest format this contract defines. Raised only for a change that
/// cannot be made by adding a key.
pub const FORMAT: u64 = 1;
/// Largest manifest, as received and as encoded, in bytes. Fits a Kuri Link
/// frame (1 MiB) with the call around it. It is also what bounds the number
/// of files: an entry takes at least 103 bytes (its SHA-256 digest alone is
/// 66), so a manifest holds at most about 2,500 files, and about 2,000 with
/// typical paths. A separate cap on the count could never be reached.
pub const MAX_MANIFEST: usize = 256 * 1024;

/// One file of a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// Where it goes, relative, `/`-separated.
    pub path: String,
    /// Its content.
    pub digest: Digest,
    /// Its size in bytes; a depot checks the blob has it.
    pub size: u64,
}

/// The system a version is for, in Rust's `std::env::consts` spellings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `OS`, such as `windows`.
    pub os: String,
    /// `ARCH`, such as `x86_64`.
    pub arch: String,
}

/// A dependency, recorded only: nothing resolves it yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    /// Its kind.
    pub kind: Kind,
    /// Its name.
    pub name: Name,
    /// Which versions; opaque.
    pub req: String,
}

/// Where a version came from. Only uploads are defined; sources, upstreams
/// and patches are reserved, and refused until they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Published as it is.
    Upload,
}

/// A manifest inside the contract, with its canonical encoding and digest.
#[derive(Debug, Clone)]
pub struct Manifest {
    value: Value,
    bytes: Vec<u8>,
    digest: Digest,
    kind: Kind,
    name: Name,
    version: Version,
    files: Vec<File>,
    meta: BTreeMap<String, String>,
    target: Option<Target>,
    deps: Vec<Dep>,
    origin: Option<Origin>,
    created: Option<u64>,
}

/// Two manifests are equal when their canonical encodings are: the same
/// manifest, whatever order its keys arrived in.
impl PartialEq for Manifest {
    fn eq(&self, other: &Manifest) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Manifest {}

fn bad(detail: impl Into<String>) -> Fault {
    Fault::new(Code::BadManifest, detail)
}

/// A rule broken inside a manifest is `bad_manifest`, whichever type caught
/// it; an unknown digest algorithm stays `unsupported_alg`.
fn inside(fault: Fault) -> Fault {
    match fault.code {
        Code::UnsupportedAlg => fault,
        _ => bad(fault.detail),
    }
}

/// A map's entries by key. The value was checked to be in the subset, so
/// keys are text and distinct.
fn fields<'a>(v: &'a Value, what: &str) -> Result<BTreeMap<&'a str, &'a Value>, Fault> {
    let Value::Map(entries) = v else {
        return Err(bad(format!("{what} is not a map")));
    };
    Ok(entries
        .iter()
        .filter_map(|(k, v)| k.as_text().map(|k| (k, v)))
        .collect())
}

fn text<'a>(map: &BTreeMap<&str, &'a Value>, key: &str, what: &str) -> Result<&'a str, Fault> {
    match map.get(key) {
        Some(Value::Text(t)) => Ok(t),
        Some(_) => Err(bad(format!("{what}.{key} is not text"))),
        None => Err(bad(format!("{what} has no {key}"))),
    }
}

fn uint(v: &Value, what: &str) -> Result<u64, Fault> {
    match v {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| bad(format!("{what} is negative"))),
        _ => Err(bad(format!("{what} is not an unsigned integer"))),
    }
}

impl Manifest {
    /// Reads a manifest from its bytes: any definite CBOR encoding inside the
    /// subset, at most [`MAX_MANIFEST`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<Manifest, Fault> {
        if bytes.len() > MAX_MANIFEST {
            return Err(Fault::new(
                Code::TooLarge,
                format!("manifest is {} bytes, over {MAX_MANIFEST}", bytes.len()),
            ));
        }
        let value = cbor::decode(bytes).map_err(|e| bad(format!("manifest has {e}")))?;
        Manifest::from_value(value)
    }

    /// Checks a manifest that arrived as a value, as inside a `publish` call.
    pub fn from_value(value: Value) -> Result<Manifest, Fault> {
        let bytes = cbor::encode(&value).map_err(|e| bad(format!("manifest has {e}")))?;
        if bytes.len() > MAX_MANIFEST {
            return Err(Fault::new(
                Code::TooLarge,
                format!(
                    "manifest encodes to {} bytes, over {MAX_MANIFEST}",
                    bytes.len()
                ),
            ));
        }
        let top = fields(&value, "manifest")?;

        let format = top
            .get("format")
            .ok_or_else(|| bad("manifest has no format"))?;
        if uint(format, "format")? != FORMAT {
            return Err(bad(format!("format {format:?} is not {FORMAT}")));
        }
        let kind = Kind::new(text(&top, "kind", "manifest")?).map_err(inside)?;
        let name = Name::new(text(&top, "name", "manifest")?).map_err(inside)?;
        let version = Version::new(text(&top, "version", "manifest")?).map_err(inside)?;
        let files = read_files(top.get("files").copied())?;

        let mut meta = BTreeMap::new();
        if let Some(v) = top.get("meta") {
            for (k, v) in fields(v, "meta")? {
                if !unicode_normalization::is_nfc(k) {
                    return Err(bad(format!("meta key {k:?} is not in Unicode NFC")));
                }
                let Value::Text(v) = v else {
                    return Err(bad(format!("meta.{k} is not text")));
                };
                meta.insert(k.to_owned(), v.clone());
            }
        }
        let target = match top.get("target") {
            None => None,
            Some(v) => {
                let t = fields(v, "target")?;
                Some(Target {
                    os: text(&t, "os", "target")?.to_owned(),
                    arch: text(&t, "arch", "target")?.to_owned(),
                })
            }
        };
        let deps = match top.get("deps") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|d| {
                    let d = fields(d, "a dep")?;
                    Ok(Dep {
                        kind: Kind::new(text(&d, "kind", "dep")?).map_err(inside)?,
                        name: Name::new(text(&d, "name", "dep")?).map_err(inside)?,
                        req: text(&d, "req", "dep")?.to_owned(),
                    })
                })
                .collect::<Result<_, Fault>>()?,
            Some(_) => return Err(bad("deps is not an array")),
        };
        let origin = match top.get("origin") {
            None => None,
            Some(v) => match text(&fields(v, "origin")?, "type", "origin")? {
                "upload" => Some(Origin::Upload),
                other => return Err(bad(format!("origin type {other:?} is not defined yet"))),
            },
        };
        let created = top.get("created").map(|v| uint(v, "created")).transpose()?;

        let digest = Digest::sha256(&bytes);
        Ok(Manifest {
            value,
            bytes,
            digest,
            kind,
            name,
            version,
            files,
            meta,
            target,
            deps,
            origin,
            created,
        })
    }

    /// The manifest as received, unknown keys included.
    pub fn value(&self) -> &Value {
        &self.value
    }
    /// The canonical encoding: what a depot stores and the digest covers.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// The manifest's identity.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    /// Its kind.
    pub fn kind(&self) -> &Kind {
        &self.kind
    }
    /// Its name.
    pub fn name(&self) -> &Name {
        &self.name
    }
    /// Its version.
    pub fn version(&self) -> &Version {
        &self.version
    }
    /// Its files, in the manifest's order.
    pub fn files(&self) -> &[File] {
        &self.files
    }
    /// Per-kind facts no depot interprets.
    pub fn meta(&self) -> &BTreeMap<String, String> {
        &self.meta
    }
    /// The system it is for; `None` means any.
    pub fn target(&self) -> Option<&Target> {
        self.target.as_ref()
    }
    /// Its dependencies, as recorded.
    pub fn deps(&self) -> &[Dep] {
        &self.deps
    }
    /// Where it came from, if the publisher said.
    pub fn origin(&self) -> Option<Origin> {
        self.origin
    }
    /// When the publisher says it was made, in milliseconds since the Unix
    /// epoch. A depot's own time is `published`, in its index.
    pub fn created(&self) -> Option<u64> {
        self.created
    }
}

fn read_files(v: Option<&Value>) -> Result<Vec<File>, Fault> {
    let Some(Value::Array(items)) = v else {
        return Err(bad("manifest has no files array"));
    };
    let files = items
        .iter()
        .map(|f| {
            let f = fields(f, "a file")?;
            let path = text(&f, "path", "file")?;
            check_path(path).map_err(bad)?;
            let digest = f
                .get("digest")
                .ok_or_else(|| bad(format!("file {path:?} has no digest")))?;
            let digest = read_digest(digest, path)?;
            let size = f
                .get("size")
                .ok_or_else(|| bad(format!("file {path:?} has no size")))?;
            Ok(File {
                path: path.to_owned(),
                digest,
                size: uint(size, "size")?,
            })
        })
        .collect::<Result<Vec<_>, Fault>>()?;
    check_paths_together(files.iter().map(|f| f.path.as_str())).map_err(bad)?;
    Ok(files)
}

/// `{alg, hex}`, exactly those two keys, as [`Digest`] reads it on the wire.
fn read_digest(v: &Value, path: &str) -> Result<Digest, Fault> {
    let d = fields(v, "a digest")?;
    if let Some(extra) = d.keys().find(|k| !matches!(**k, "alg" | "hex")) {
        return Err(bad(format!("the digest of {path:?} has the key {extra:?}")));
    }
    let alg = text(&d, "alg", "digest")?;
    let hex = text(&d, "hex", "digest")?;
    Digest::new(alg, hex).map_err(inside)
}

/// Builds a manifest from typed parts. The result goes through the same
/// checks as one received.
#[derive(Debug, Clone)]
pub struct ManifestBuilder {
    entries: Vec<(Value, Value)>,
    files: Vec<Value>,
}

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

impl ManifestBuilder {
    /// A manifest for `version` of `name`, of `kind`.
    pub fn new(kind: &Kind, name: &Name, version: &Version) -> ManifestBuilder {
        ManifestBuilder {
            entries: vec![
                (t("format"), Value::Integer(FORMAT.into())),
                (t("kind"), t(kind.as_str())),
                (t("name"), t(name.as_str())),
                (t("version"), t(version.as_str())),
            ],
            files: Vec::new(),
        }
    }

    /// Adds a file.
    pub fn file(mut self, path: &str, digest: &Digest, size: u64) -> Self {
        let digest = Value::serialized(digest).expect("a digest serializes");
        self.files.push(Value::Map(vec![
            (t("path"), t(path)),
            (t("digest"), digest),
            (t("size"), Value::Integer(size.into())),
        ]));
        self
    }

    /// Sets `meta`.
    pub fn meta<'a>(mut self, meta: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let map = meta.into_iter().map(|(k, v)| (t(k), t(v))).collect();
        self.entries.push((t("meta"), Value::Map(map)));
        self
    }

    /// Sets `target`.
    pub fn target(mut self, os: &str, arch: &str) -> Self {
        let map = vec![(t("os"), t(os)), (t("arch"), t(arch))];
        self.entries.push((t("target"), Value::Map(map)));
        self
    }

    /// Sets `deps`.
    pub fn deps(mut self, deps: &[Dep]) -> Self {
        let deps = deps
            .iter()
            .map(|d| {
                Value::Map(vec![
                    (t("kind"), t(d.kind.as_str())),
                    (t("name"), t(d.name.as_str())),
                    (t("req"), t(&d.req)),
                ])
            })
            .collect();
        self.entries.push((t("deps"), Value::Array(deps)));
        self
    }

    /// Sets `origin`.
    pub fn origin(mut self, origin: Origin) -> Self {
        let Origin::Upload = origin;
        let map = vec![(t("type"), t("upload"))];
        self.entries.push((t("origin"), Value::Map(map)));
        self
    }

    /// Sets `created`, in milliseconds since the Unix epoch.
    pub fn created(mut self, ms: u64) -> Self {
        self.entries.push((t("created"), Value::Integer(ms.into())));
        self
    }

    /// Checks and encodes the manifest.
    pub fn build(self) -> Result<Manifest, Fault> {
        let mut entries = self.entries;
        entries.push((t("files"), Value::Array(self.files)));
        Manifest::from_value(Value::Map(entries))
    }
}

#[cfg(test)]
mod tests;
