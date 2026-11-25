//! The depot: the app `pub` over a [`Store`] and an [`Index`].

use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::ops::Bound;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use kuri_link::{AppError, BoxFuture, Caller, Duplex, OpenHandler, Service, Value};
use kuri_pub::methods::{
    self, At, ChannelPointer, Empty, GetArgs, HasArgs, KindCount, ListArgs, ListItem, ListPage,
    ManifestArgs, ManifestReply, PublishArgs, PublishReply, PutArgs, PutResult, SetChannelArgs,
    SetChannelReply, VersionItem, VersionsArgs, VersionsPage,
};
use kuri_pub::names::{MAX_NAME, MAX_VERSION};
use kuri_pub::{Code, Digest, Fault, Manifest, ReportedDigest, cbor};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::index::{Index, Record};
use crate::store::Store;

/// How a depot is set up.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The largest blob a `put` may store, in bytes.
    pub max_blob: u64,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            max_blob: methods::DEFAULT_MAX_BLOB,
        }
    }
}

/// How many missing blobs a `missing_blobs` fault names; it counts the rest.
pub const MISSING_SHOWN: usize = 5;

/// The chunk a `get` reads and sends at a time, so its memory does not
/// depend on the blob's size.
pub const GET_CHUNK: usize = 64 * 1024;

/// A depot over one store directory. Serve it as [`kuri_pub::APP`].
#[derive(Debug)]
pub struct Depot {
    store: Store,
    index: Mutex<Index>,
    settings: Settings,
}

impl Depot {
    /// Opens the depot whose store is `dir`, creating it if it is new.
    pub fn open(dir: &Path, settings: Settings) -> io::Result<Depot> {
        let store = Store::open(dir)?;
        let index = Index::open(&dir.join("index"))?;
        Ok(Depot {
            store,
            index: Mutex::new(index),
            settings,
        })
    }

    /// Answers a `call`.
    pub fn call(&self, method: &str, args: Value) -> Result<Result<Value, Fault>, AppError> {
        Ok(match method {
            methods::KINDS => self.kinds(args).and_then(encode),
            methods::LIST => self.list(args).and_then(encode),
            methods::VERSIONS => self.versions(args).and_then(encode),
            methods::MANIFEST => self.manifest(args).and_then(encode),
            methods::HAS => self.has(args).and_then(encode),
            methods::PUBLISH => self.publish(args).and_then(encode),
            methods::SET_CHANNEL => self.set_channel(args).and_then(encode),
            other => return Err(AppError::NoSuchMethod(other.to_owned())),
        })
    }

    fn index(&self) -> std::sync::MutexGuard<'_, Index> {
        self.index.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn kinds(&self, args: Value) -> Result<Vec<KindCount>, Fault> {
        let Empty {} = parse(args, Code::BadName)?;
        Ok(self
            .index()
            .kinds()
            .iter()
            .map(|(kind, names)| KindCount {
                kind: kind.clone(),
                names: names.len() as u64,
            })
            .collect())
    }

    fn list(&self, args: Value) -> Result<ListPage, Fault> {
        let args: ListArgs = parse(args, Code::BadName)?;
        cursor(args.after.as_deref(), MAX_NAME)?;
        let size = methods::page_size(args.limit);
        let index = self.index();
        let Some(names) = index.kinds().get(args.kind.as_str()) else {
            return Ok(ListPage {
                items: Vec::new(),
                next: None,
            });
        };
        let start = match &args.after {
            Some(after) => Bound::Excluded(after.as_str()),
            None => Bound::Unbounded,
        };
        let mut items: Vec<ListItem> = names
            .range::<str, _>((start, Bound::Unbounded))
            .take(size + 1)
            .map(|(name, entry)| ListItem {
                name: name.clone(),
                versions: entry.versions.len() as u64,
                channels: entry
                    .channels
                    .iter()
                    .map(|(c, p)| {
                        (
                            c.clone(),
                            ChannelPointer {
                                version: p.version.clone(),
                                seq: p.seq,
                            },
                        )
                    })
                    .collect(),
            })
            .collect();
        let next = if items.len() > size {
            items.truncate(size);
            items.last().map(|i| i.name.clone())
        } else {
            None
        };
        Ok(ListPage { items, next })
    }

    fn versions(&self, args: Value) -> Result<VersionsPage, Fault> {
        let args: VersionsArgs = parse(args, Code::BadName)?;
        cursor(args.after.as_deref(), MAX_VERSION)?;
        let size = methods::page_size(args.limit);
        let index = self.index();
        let entry = index
            .entry(args.kind.as_str(), args.name.as_str())
            .filter(|e| !e.versions.is_empty())
            .ok_or_else(|| not_found(format!("{} {}", args.kind, args.name)))?;
        let start = match &args.after {
            Some(after) => {
                entry
                    .position(after)
                    .ok_or_else(|| not_found(format!("no version {after:?} to page after")))?
                    + 1
            }
            None => 0,
        };
        let rest = &entry.versions[start.min(entry.versions.len())..];
        let items: Vec<VersionItem> = rest
            .iter()
            .take(size)
            .map(|v| VersionItem {
                version: v.version.clone(),
                manifest: ReportedDigest::from(v.digest.clone()),
                published: v.published,
            })
            .collect();
        let next = (rest.len() > size)
            .then(|| items.last().map(|i| i.version.clone()))
            .flatten();
        Ok(VersionsPage { items, next })
    }

    fn manifest(&self, args: Value) -> Result<ManifestReply, Fault> {
        let args: ManifestArgs = parse(args, Code::BadName)?;
        let at = args.at()?;
        let (version, digest, seq) = {
            let index = self.index();
            let entry = index
                .entry(args.kind.as_str(), args.name.as_str())
                .ok_or_else(|| not_found(format!("{} {}", args.kind, args.name)))?;
            let (version, seq) = match at {
                At::Version(v) => (v.as_str().to_owned(), None),
                At::Channel(c) => {
                    let p = entry
                        .channels
                        .get(c.as_str())
                        .ok_or_else(|| not_found(format!("channel {c}")))?;
                    (p.version.clone(), Some(p.seq))
                }
            };
            let rec = entry
                .version(&version)
                .ok_or_else(|| not_found(format!("version {version}")))?;
            (version, rec.digest.clone(), seq)
        };
        let bytes = self.store.read(&digest).map_err(storage)?;
        let manifest = cbor::decode(&bytes).map_err(|e| {
            Fault::new(
                Code::Storage,
                format!("stored manifest {digest} does not decode: {e}"),
            )
        })?;
        Ok(ManifestReply {
            version,
            digest: ReportedDigest::from(digest),
            manifest,
            seq,
        })
    }

    fn has(&self, args: Value) -> Result<Vec<bool>, Fault> {
        let args: HasArgs = parse(args, Code::BadName)?;
        args.check()?;
        args.digests
            .iter()
            .map(|d| Ok(self.store.size(d).map_err(storage)?.is_some()))
            .collect()
    }

    fn publish(&self, args: Value) -> Result<PublishReply, Fault> {
        let args: PublishArgs = parse(args, Code::BadManifest)?;
        let manifest = Manifest::from_value(args.manifest)?;
        let mut missing = Vec::new();
        for f in manifest.files() {
            match self.store.size(&f.digest).map_err(storage)? {
                Some(size) if size == f.size => {}
                Some(size) => missing.push(format!(
                    "{} ({}: {size} bytes stored, {} claimed)",
                    f.digest, f.path, f.size
                )),
                None => missing.push(format!("{} ({})", f.digest, f.path)),
            }
        }
        if !missing.is_empty() {
            // For people, and bounded: a manifest can name thousands of files.
            let shown = missing.len().min(MISSING_SHOWN);
            let more = missing.len() - shown;
            return Err(Fault::new(
                Code::MissingBlobs,
                format!(
                    "{} of {} files not stored: {}{}",
                    missing.len(),
                    manifest.files().len(),
                    missing[..shown].join(", "),
                    if more > 0 {
                        format!(", and {more} more")
                    } else {
                        String::new()
                    }
                ),
            ));
        }
        let digest = manifest.digest().clone();
        let mut index = self.index();
        if let Some(stored) = index
            .entry(manifest.kind().as_str(), manifest.name().as_str())
            .and_then(|e| e.version(manifest.version().as_str()))
        {
            return if stored.digest == digest {
                Ok(PublishReply {
                    digest: digest.into(),
                    created: false,
                })
            } else {
                Err(methods::conflict(&stored.digest))
            };
        }
        // The manifest is on disk before the index names it, so an index entry
        // never points at a blob that is not there.
        self.store
            .put_bytes(&digest, manifest.bytes())
            .map_err(storage)?;
        index
            .append(Record::Publish {
                kind: manifest.kind().to_string(),
                name: manifest.name().to_string(),
                version: manifest.version().to_string(),
                digest: digest.clone(),
                published: now_ms(),
            })
            .map_err(storage)?;
        Ok(PublishReply {
            digest: digest.into(),
            created: true,
        })
    }

    fn set_channel(&self, args: Value) -> Result<SetChannelReply, Fault> {
        let args: SetChannelArgs = parse(args, Code::BadName)?;
        let mut index = self.index();
        let entry = index
            .entry(args.kind.as_str(), args.name.as_str())
            .ok_or_else(|| not_found(format!("{} {}", args.kind, args.name)))?;
        if entry.version(args.version.as_str()).is_none() {
            return Err(not_found(format!("version {}", args.version)));
        }
        let current = entry.channels.get(args.channel.as_str());
        let seq = current.map_or(0, |c| c.seq);
        let previous = current.map(|c| c.version.clone());
        if let Some(expect) = args.expect
            && expect != seq
        {
            return Err(Fault::new(
                Code::ChannelMoved,
                format!("channel {} is at {seq}, not {expect}", args.channel),
            ));
        }
        index
            .append(Record::Channel {
                kind: args.kind.to_string(),
                name: args.name.to_string(),
                channel: args.channel.to_string(),
                version: args.version.to_string(),
                seq: seq + 1,
            })
            .map_err(storage)?;
        Ok(SetChannelReply {
            previous,
            seq: seq + 1,
        })
    }

    /// Decides whether to accept an `open`, and how to run it if so.
    pub fn accept(
        self: &Arc<Self>,
        method: &str,
        args: Value,
    ) -> Result<Result<Opened, Fault>, AppError> {
        Ok(match method {
            methods::GET => self.accept_get(args).map(Opened::Get),
            methods::PUT => self.accept_put(args).map(Opened::Put),
            other => return Err(AppError::NoSuchMethod(other.to_owned())),
        })
    }

    fn accept_get(&self, args: Value) -> Result<Get, Fault> {
        let args: GetArgs = parse(args, Code::BadName)?;
        let mut file = match File::open(self.store.path(&args.digest)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(not_found(format!("blob {}", args.digest)));
            }
            Err(e) => return Err(storage(e)),
        };
        let size = file.metadata().map_err(storage)?.len();
        let offset = args.offset.unwrap_or(0);
        if offset > size {
            return Err(Fault::new(
                Code::BadRange,
                format!("offset {offset} is past the end ({size} bytes)"),
            ));
        }
        file.seek(SeekFrom::Start(offset)).map_err(storage)?;
        Ok(Get { file })
    }

    fn accept_put(self: &Arc<Self>, args: Value) -> Result<Put, Fault> {
        let args: PutArgs = parse(args, Code::BadName)?;
        if args.size > self.settings.max_blob {
            return Err(Fault::new(
                Code::TooLarge,
                format!(
                    "{} bytes, over this depot's {} per blob",
                    args.size, self.settings.max_blob
                ),
            ));
        }
        Ok(Put {
            depot: self.clone(),
            digest: args.digest,
            size: args.size,
        })
    }
}

/// An accepted `open`.
pub enum Opened {
    /// A `get`, ready to stream.
    Get(Get),
    /// A `put`, ready to receive.
    Put(Put),
}

impl Opened {
    /// Runs the stream to its end.
    pub async fn run(self, io: Duplex) {
        // The stream is the outcome; a failure here is the peer's to see.
        let _ = match self {
            Opened::Get(g) => g.run(io).await,
            Opened::Put(p) => p.run(io).await,
        };
    }
}

/// A `get` that has been accepted: the blob open at the requested offset.
pub struct Get {
    file: File,
}

impl Get {
    async fn run(self, mut io: Duplex) -> io::Result<()> {
        let mut file = tokio::fs::File::from_std(self.file);
        let mut buf = vec![0u8; GET_CHUNK];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            io.send.write_all(&buf[..n]).await?;
        }
        io.send.shutdown().await
    }
}

/// A `put` that has been accepted.
pub struct Put {
    depot: Arc<Depot>,
    digest: Digest,
    size: u64,
}

impl Put {
    async fn run(self, mut io: Duplex) -> io::Result<()> {
        let result = match self.depot.store.size(&self.digest) {
            // Already stored: say so at once and read nothing more.
            Ok(Some(_)) => PutResult::Stored { stored: false },
            Ok(None) => match self.receive(&mut io).await {
                Ok(()) => PutResult::Stored { stored: true },
                Err(fault) => fault.into(),
            },
            Err(e) => storage(e).into(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&result, &mut bytes).map_err(io::Error::other)?;
        io.send.write_all(&bytes).await?;
        io.send.shutdown().await
    }

    /// Streams the upload into a temporary file while hashing it, then checks
    /// it and moves it into place. Whatever goes wrong, no partial blob is
    /// left under the digest's name.
    async fn receive(&self, io: &mut Duplex) -> Result<(), Fault> {
        let store = &self.depot.store;
        let (tmp, file) = store.temporary().map_err(storage)?;
        // Removes the file however this ends short of a commit: a fault, or
        // the stream's future dropped mid-upload when its connection went.
        let mut guard = TmpGuard(Some(tmp.clone()));
        let file = self.write(io, file).await?.into_std().await;
        let (depot, digest) = (self.depot.clone(), self.digest.clone());
        tokio::task::spawn_blocking(move || depot.store.commit(&tmp, file, &digest))
            .await
            .map_err(|e| Fault::new(Code::Storage, e.to_string()))?
            .map_err(storage)?;
        guard.0 = None;
        Ok(())
    }

    async fn write(&self, io: &mut Duplex, file: File) -> Result<tokio::fs::File, Fault> {
        let mut file = tokio::fs::File::from_std(file);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; methods::PUT_BUFFER];
        let mut got = 0u64;
        loop {
            let n = io
                .recv
                .read(&mut buf)
                .await
                .map_err(|e| Fault::new(Code::Storage, format!("reading the upload: {e}")))?;
            if n == 0 {
                break;
            }
            got += n as u64;
            if got > self.size {
                return Err(Fault::new(
                    Code::SizeMismatch,
                    format!("more than the {} bytes announced", self.size),
                ));
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).await.map_err(storage)?;
        }
        if got != self.size {
            return Err(Fault::new(
                Code::SizeMismatch,
                format!("{got} bytes, {} announced", self.size),
            ));
        }
        let actual = Digest::from_sha256(hasher.finalize().into());
        if actual != self.digest {
            return Err(Fault::new(
                Code::DigestMismatch,
                format!("the bytes hash to {actual}, not {}", self.digest),
            ));
        }
        file.flush().await.map_err(storage)?;
        Ok(file)
    }
}

/// Deletes an upload's temporary file when dropped, unless it was committed.
struct TmpGuard(Option<std::path::PathBuf>);

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The depot as a Kuri Link service.
#[derive(Debug, Clone)]
pub struct DepotService(pub Arc<Depot>);

impl Service for DepotService {
    fn call(
        self: Arc<Self>,
        _caller: Caller,
        method: String,
        args: Value,
    ) -> BoxFuture<'static, Result<Value, AppError>> {
        Box::pin(async move {
            let depot = self.0.clone();
            // The index syncs its log on every change, and manifests are read
            // from disk: blocking work, kept off the async threads.
            tokio::task::spawn_blocking(move || depot.call(&method, args))
                .await
                .map_err(|e| {
                    AppError::Failed(Fault::new(Code::Storage, e.to_string()).to_string())
                })??
                .map_err(|f| AppError::Failed(f.to_string()))
        })
    }

    fn accept_open(
        self: Arc<Self>,
        _caller: Caller,
        method: String,
        args: Value,
    ) -> BoxFuture<'static, Result<OpenHandler, AppError>> {
        Box::pin(async move {
            let depot = self.0.clone();
            let opened = tokio::task::spawn_blocking(move || depot.accept(&method, args))
                .await
                .map_err(|e| {
                    AppError::Failed(Fault::new(Code::Storage, e.to_string()).to_string())
                })??
                .map_err(|f| AppError::Failed(f.to_string()))?;
            let run: OpenHandler = Box::new(move |io| Box::pin(opened.run(io)));
            Ok(run)
        })
    }

    fn method_names(&self) -> Vec<String> {
        [
            methods::KINDS,
            methods::LIST,
            methods::VERSIONS,
            methods::MANIFEST,
            methods::HAS,
            methods::PUBLISH,
            methods::SET_CHANNEL,
            methods::GET,
            methods::PUT,
        ]
        .map(String::from)
        .to_vec()
    }
}

/// Reads a request's arguments. A refusal from a checked type keeps its own
/// code (`unsupported_alg` for a digest, `bad_name` for a name); any other
/// shape problem is `otherwise`.
fn parse<T: DeserializeOwned>(args: Value, otherwise: Code) -> Result<T, Fault> {
    args.deserialized().map_err(|e| {
        let message = e.to_string();
        // The fault a checked type raised is the first code in the text; a
        // later one can only be part of its detail, such as a digest
        // algorithm spelt like a code.
        kuri_pub::fault::CODES
            .iter()
            .filter_map(|code| message.find(&format!("{}: ", code.as_str())))
            .min()
            .map(|at| Fault::parse(message[at..].trim_end_matches(['"', ')'])))
            .unwrap_or_else(|| Fault::new(otherwise, message))
    })
}

/// A paging cursor is text the depot only compares; it still may not be
/// longer than anything it could name.
fn cursor(after: Option<&str>, max: usize) -> Result<(), Fault> {
    match after {
        Some(a) if a.len() > max => Err(Fault::new(
            Code::BadName,
            format!("cursor of {} bytes, over {max}", a.len()),
        )),
        _ => Ok(()),
    }
}

fn encode<T: Serialize>(t: T) -> Result<Value, Fault> {
    Value::serialized(&t).map_err(|e| Fault::new(Code::Storage, format!("encoding a reply: {e}")))
}

fn not_found(what: impl Into<String>) -> Fault {
    Fault::new(Code::NotFound, what)
}

fn storage(e: io::Error) -> Fault {
    Fault::new(Code::Storage, e.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
