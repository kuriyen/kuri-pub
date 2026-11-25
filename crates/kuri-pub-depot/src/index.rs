//! The index: which versions exist and where each channel points.
//!
//! ```text
//! <store>/index/log        append-only records, each synced before it counts
//! <store>/index/snapshot   every record the log held when it was compacted
//! ```
//!
//! A record is a version published or a channel moved. Each one in the log is
//! framed as a 4-byte little-endian length, a 4-byte CRC-32 of the payload,
//! and the payload, a CBOR map. An append is synced before the request that
//! made it is answered, so an answer the client saw survives a crash.
//!
//! On start the index loads the snapshot, replays the log over it, and cuts
//! off a torn last record: a bad frame (short, a failed checksum, a length no
//! record can have) that reaches the end of the file, as a crash in the middle
//! of an append leaves. A bad frame with more data after it is not a torn
//! write but damage, and the records after it were answered: the index then
//! refuses to open and names the offset, for a person to look at. An append
//! that fails is cut back off the log before the error is returned, so the
//! next record never lands behind it; if it cannot be cut back, the index
//! refuses every later write until the depot restarts. Replaying a record twice
//! changes nothing, so a crash between writing a snapshot and emptying the log
//! loses nothing either. The state lives in memory: it holds names and
//! digests, not content.
//!
//! The snapshot is written to a temporary file, synced, and renamed over the
//! old one; only then is the log emptied.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use kuri_pub::Digest;
use serde::{Deserialize, Serialize};

use crate::store::sync_dir;

/// The log is compacted into the snapshot once it holds this many records.
pub const COMPACT_AFTER: usize = 4096;

/// The largest record a log may hold. Names are short; anything larger is a
/// damaged frame, not a record.
const MAX_RECORD: u32 = 64 * 1024;

/// One change to the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Record {
    /// A version was recorded.
    Publish {
        /// Its kind.
        kind: String,
        /// Its name.
        name: String,
        /// Its version.
        version: String,
        /// Its manifest's digest.
        digest: Digest,
        /// When, in milliseconds since the Unix epoch.
        published: u64,
    },
    /// A channel moved.
    Channel {
        /// The kind.
        kind: String,
        /// The name.
        name: String,
        /// The channel.
        channel: String,
        /// Where it points now.
        version: String,
        /// Its position after the move.
        seq: u64,
    },
}

/// One version of a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRec {
    /// The version.
    pub version: String,
    /// Its manifest's digest.
    pub digest: Digest,
    /// When the depot recorded it.
    pub published: u64,
}

/// Where a channel points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRec {
    /// The version.
    pub version: String,
    /// How many times it has moved.
    pub seq: u64,
}

/// Everything known about one name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// Its versions in the order they were published.
    pub versions: Vec<VersionRec>,
    by_version: HashMap<String, usize>,
    /// Its channels.
    pub channels: BTreeMap<String, ChannelRec>,
}

impl Entry {
    /// The position of `version` in [`Entry::versions`].
    pub fn position(&self, version: &str) -> Option<usize> {
        self.by_version.get(version).copied()
    }

    /// The record of `version`.
    pub fn version(&self, version: &str) -> Option<&VersionRec> {
        self.position(version).map(|i| &self.versions[i])
    }
}

/// The index's state: kind → name → entry, each level in bytewise order.
pub type Kinds = BTreeMap<String, BTreeMap<String, Entry>>;

/// The index of one store.
#[derive(Debug)]
pub struct Index {
    dir: PathBuf,
    log: File,
    /// The log's length after its last whole record.
    len: u64,
    in_log: usize,
    kinds: Kinds,
    /// Why writes are refused, once an append could not be cut back.
    broken: Option<String>,
    #[cfg(test)]
    fail: Fail,
}

/// Failures a test injects into the log's I/O.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
struct Fail {
    /// The write stops halfway.
    write: bool,
    /// The write lands, the sync fails.
    sync: bool,
    /// Cutting the log back fails.
    cut: bool,
}

impl Index {
    /// Opens the index in `dir`, creating it if it is new.
    pub fn open(dir: &Path) -> io::Result<Index> {
        fs::create_dir_all(dir)?;
        let mut kinds = Kinds::new();
        match fs::read(dir.join("snapshot")) {
            Ok(bytes) => {
                let records: Vec<Record> =
                    ciborium::from_reader(bytes.as_slice()).map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("snapshot: {e}"))
                    })?;
                for r in &records {
                    apply(&mut kinds, r);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let log_path = dir.join("log");
        let mut log = File::options()
            .read(true)
            .append(true)
            .create(true)
            .open(&log_path)?;
        let file_len = log.metadata()?.len();
        let (records, good) = read_log(&mut log, file_len)?;
        if good < file_len {
            // A torn last record: the append it belonged to was never
            // answered, so dropping it loses nothing a client was told.
            log.set_len(good)?;
            log.sync_all()?;
        }
        for r in &records {
            apply(&mut kinds, r);
        }
        sync_dir(dir)?;
        let mut index = Index {
            dir: dir.to_owned(),
            log,
            len: good,
            in_log: records.len(),
            kinds,
            broken: None,
            #[cfg(test)]
            fail: Fail::default(),
        };
        if index.in_log > 0 {
            index.compact()?;
        }
        Ok(index)
    }

    /// The state.
    pub fn kinds(&self) -> &Kinds {
        &self.kinds
    }

    /// The entry of `(kind, name)`.
    pub fn entry(&self, kind: &str, name: &str) -> Option<&Entry> {
        self.kinds.get(kind).and_then(|names| names.get(name))
    }

    /// Records `record`: appends it to the log, syncs it, then applies it.
    ///
    /// On failure nothing is applied, and the log is cut back to where it
    /// was, so the next append does not land behind a partial or unsynced
    /// frame. If that fails too, this and every later append is refused.
    pub fn append(&mut self, record: Record) -> io::Result<()> {
        if let Some(why) = &self.broken {
            return Err(io::Error::other(format!(
                "the index refuses writes until the depot restarts: {why}"
            )));
        }
        let mut payload = Vec::new();
        ciborium::into_writer(&record, &mut payload)
            .map_err(|e| io::Error::other(format!("encoding a record: {e}")))?;
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        frame.extend_from_slice(&payload);
        if let Err(e) = self.write_frame(&frame) {
            if let Err(cut) = self.cut_back() {
                self.broken = Some(format!(
                    "an append failed ({e}) and could not be cut back off the log ({cut})"
                ));
            }
            return Err(e);
        }
        self.len += frame.len() as u64;
        apply(&mut self.kinds, &record);
        self.in_log += 1;
        if self.in_log >= COMPACT_AFTER {
            self.compact()?;
        }
        Ok(())
    }

    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if self.fail.write {
            self.log.write_all(&frame[..frame.len() / 2])?;
            return Err(io::Error::other("injected: the write stopped halfway"));
        }
        self.log.write_all(frame)?;
        #[cfg(test)]
        if self.fail.sync {
            return Err(io::Error::other("injected: the sync failed"));
        }
        self.log.sync_data()
    }

    /// Cuts the log back to its last whole record.
    fn cut_back(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if self.fail.cut {
            return Err(io::Error::other("injected: the cut failed"));
        }
        self.log.set_len(self.len)?;
        self.log.sync_all()
    }

    /// Writes the state as the snapshot and empties the log.
    pub fn compact(&mut self) -> io::Result<()> {
        let mut records = Vec::new();
        for (kind, names) in &self.kinds {
            for (name, entry) in names {
                for v in &entry.versions {
                    records.push(Record::Publish {
                        kind: kind.clone(),
                        name: name.clone(),
                        version: v.version.clone(),
                        digest: v.digest.clone(),
                        published: v.published,
                    });
                }
                for (channel, c) in &entry.channels {
                    records.push(Record::Channel {
                        kind: kind.clone(),
                        name: name.clone(),
                        channel: channel.clone(),
                        version: c.version.clone(),
                        seq: c.seq,
                    });
                }
            }
        }
        let tmp = self.dir.join("snapshot.tmp");
        let mut file = File::create(&tmp)?;
        ciborium::into_writer(&records, &mut file)
            .map_err(|e| io::Error::other(format!("encoding the snapshot: {e}")))?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, self.dir.join("snapshot"))?;
        sync_dir(&self.dir)?;
        // Only now is the log's content in the snapshot; a crash before this
        // line replays it over the snapshot, which changes nothing.
        self.log.set_len(0)?;
        self.log.sync_all()?;
        self.len = 0;
        self.in_log = 0;
        Ok(())
    }
}

/// Applies `record` to `kinds`. Applying one twice is the same as once.
fn apply(kinds: &mut Kinds, record: &Record) {
    match record {
        Record::Publish {
            kind,
            name,
            version,
            digest,
            published,
        } => {
            let entry = kinds
                .entry(kind.clone())
                .or_default()
                .entry(name.clone())
                .or_default();
            if entry.by_version.contains_key(version) {
                return;
            }
            entry
                .by_version
                .insert(version.clone(), entry.versions.len());
            entry.versions.push(VersionRec {
                version: version.clone(),
                digest: digest.clone(),
                published: *published,
            });
        }
        Record::Channel {
            kind,
            name,
            channel,
            version,
            seq,
        } => {
            let entry = kinds
                .entry(kind.clone())
                .or_default()
                .entry(name.clone())
                .or_default();
            let current = entry.channels.get(channel).map_or(0, |c| c.seq);
            if *seq > current {
                entry.channels.insert(
                    channel.clone(),
                    ChannelRec {
                        version: version.clone(),
                        seq: *seq,
                    },
                );
            }
        }
    }
}

/// Reads the log's records, and the length of the part that holds whole,
/// intact ones. A bad frame that reaches the end of the file is a torn write
/// and ends the log there; one with data after it is damage, and an error.
fn read_log(log: &mut File, file_len: u64) -> io::Result<(Vec<Record>, u64)> {
    log.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(&*log);
    let mut records = Vec::new();
    let mut good = 0u64;
    loop {
        let mut head = [0u8; 8];
        if !read_full(&mut reader, &mut head)? {
            break;
        }
        let len = u32::from_le_bytes(head[..4].try_into().unwrap());
        let crc = u32::from_le_bytes(head[4..].try_into().unwrap());
        let end = good + 8 + u64::from(len);
        let whole = len <= MAX_RECORD && end <= file_len;
        let record = if whole {
            let mut payload = vec![0u8; len as usize];
            if !read_full(&mut reader, &mut payload)? {
                break;
            }
            (crc32fast::hash(&payload) == crc)
                .then(|| ciborium::from_reader::<Record, _>(payload.as_slice()).ok())
                .flatten()
        } else {
            None
        };
        match record {
            Some(record) => {
                records.push(record);
                good = end;
            }
            // Torn: the bad frame runs to the end of the file, or past it.
            None if end >= file_len => break,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the index log is damaged at byte {good} of {file_len}: a bad record \
                         with whole records after it, so not a torn write; those records \
                         were answered and are not dropped. Move the log aside to start \
                         without them."
                    ),
                ));
            }
        }
    }
    Ok((records, good))
}

/// Fills `buf`, or returns `false` at the end of the file, whole or partway.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut at = 0;
    while at < buf.len() {
        match r.read(&mut buf[at..])? {
            0 => return Ok(false),
            n => at += n,
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish(name: &str, version: &str) -> Record {
        Record::Publish {
            kind: "app".into(),
            name: name.into(),
            version: version.into(),
            digest: Digest::sha256(version.as_bytes()),
            published: 1,
        }
    }

    fn channel(version: &str, seq: u64) -> Record {
        Record::Channel {
            kind: "app".into(),
            name: "x".into(),
            channel: "stable".into(),
            version: version.into(),
            seq,
        }
    }

    #[test]
    fn records_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        index.append(publish("x", "2")).unwrap();
        index.append(channel("2", 1)).unwrap();
        let before = index.kinds().clone();
        drop(index);
        let index = Index::open(dir.path()).unwrap();
        assert_eq!(index.kinds(), &before);
        let e = index.entry("app", "x").unwrap();
        assert_eq!(e.versions.len(), 2);
        assert_eq!(e.position("2"), Some(1));
        assert_eq!(e.channels["stable"].seq, 1);
    }

    #[test]
    fn a_torn_last_record_is_cut_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        // Open compacts an empty log to nothing; append two records after.
        index.append(publish("x", "1")).unwrap();
        index.append(publish("x", "2")).unwrap();
        drop(index);
        let log = dir.path().join("log");
        let len = fs::metadata(&log).unwrap().len();
        for cut in [1u64, 5, 9] {
            let copy = tempfile::tempdir().unwrap();
            fs::copy(&log, copy.path().join("log")).unwrap();
            let f = File::options()
                .write(true)
                .open(copy.path().join("log"))
                .unwrap();
            f.set_len(len - cut).unwrap();
            drop(f);
            let index = Index::open(copy.path()).unwrap();
            let e = index.entry("app", "x").unwrap();
            assert_eq!(e.versions.len(), 1, "cut {cut}");
            assert_eq!(e.versions[0].version, "1");
        }
    }

    #[test]
    fn a_damaged_record_ends_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        index.append(publish("x", "2")).unwrap();
        drop(index);
        let log = dir.path().join("log");
        let mut bytes = fs::read(&log).unwrap();
        // The last byte is `published: 1`; as 2 the record still decodes, so
        // only the checksum tells it was damaged.
        let last = bytes.len() - 1;
        assert_eq!(bytes[last], 1);
        bytes[last] = 2;
        fs::write(&log, &bytes).unwrap();
        let index = Index::open(dir.path()).unwrap();
        assert_eq!(index.entry("app", "x").unwrap().versions.len(), 1);
    }

    #[test]
    fn damage_before_whole_records_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        index.append(publish("x", "2")).unwrap();
        drop(index);
        let log = dir.path().join("log");
        let mut bytes = fs::read(&log).unwrap();
        bytes[8] ^= 0x01;
        fs::write(&log, &bytes).unwrap();
        let e = Index::open(dir.path()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("at byte 0 of"), "{e}");
        // Nothing was cut.
        assert_eq!(fs::read(&log).unwrap(), bytes);
    }

    fn versions(index: &Index) -> Vec<String> {
        index
            .entry("app", "x")
            .unwrap()
            .versions
            .iter()
            .map(|v| v.version.clone())
            .collect()
    }

    #[test]
    fn a_write_that_stops_halfway_is_cut_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        index.fail.write = true;
        index.append(publish("x", "2")).unwrap_err();
        index.fail.write = false;
        assert_eq!(versions(&index), ["1"]);
        index.append(publish("x", "3")).unwrap();
        drop(index);
        assert_eq!(versions(&Index::open(dir.path()).unwrap()), ["1", "3"]);
    }

    #[test]
    fn a_failed_sync_is_cut_back() {
        // The failed move and the next one carry the same position; only the
        // one the client was told succeeded may survive a restart.
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        index.append(channel("1", 1)).unwrap();
        index.fail.sync = true;
        index.append(channel("2", 2)).unwrap_err();
        index.fail.sync = false;
        assert_eq!(index.entry("app", "x").unwrap().channels["stable"].seq, 1);
        index.append(channel("3", 2)).unwrap();
        drop(index);
        let index = Index::open(dir.path()).unwrap();
        let c = &index.entry("app", "x").unwrap().channels["stable"];
        assert_eq!((c.version.as_str(), c.seq), ("3", 2));
    }

    #[test]
    fn an_append_that_cannot_be_cut_back_stops_writes() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        index.fail.write = true;
        index.fail.cut = true;
        index.append(publish("x", "2")).unwrap_err();
        index.fail = Fail::default();
        let e = index.append(publish("x", "3")).unwrap_err();
        assert!(e.to_string().contains("refuses writes"), "{e}");
        // What was answered before is still there after a restart, which cuts
        // the partial frame off as a torn tail.
        drop(index);
        assert_eq!(versions(&Index::open(dir.path()).unwrap()), ["1"]);
    }

    #[test]
    fn a_log_that_is_only_a_torn_record_still_takes_appends() {
        // Nothing whole to replay, so no compaction empties the log: the torn
        // bytes have to be cut, or every later append lands behind them.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("log"), [9, 0, 0, 0, 1]).unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        drop(index);
        let index = Index::open(dir.path()).unwrap();
        assert_eq!(index.entry("app", "x").unwrap().versions.len(), 1);
    }

    #[test]
    fn a_record_over_the_limit_is_not_read() {
        // Whole and with a good checksum, but longer than any record can be:
        // a damaged length, so the log ends before it.
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        drop(index);
        let mut payload = Vec::new();
        ciborium::into_writer(
            &publish(&"y".repeat(MAX_RECORD as usize), "1"),
            &mut payload,
        )
        .unwrap();
        let mut bytes = fs::read(dir.path().join("log")).unwrap();
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        bytes.extend_from_slice(&payload);
        fs::write(dir.path().join("log"), &bytes).unwrap();
        let index = Index::open(dir.path()).unwrap();
        assert_eq!(index.kinds()["app"].len(), 1);
    }

    #[test]
    fn compaction_keeps_everything_and_empties_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        for v in 0..10 {
            index.append(publish("x", &v.to_string())).unwrap();
        }
        index.append(channel("3", 1)).unwrap();
        index.append(channel("7", 2)).unwrap();
        let before = index.kinds().clone();
        index.compact().unwrap();
        assert_eq!(fs::metadata(dir.path().join("log")).unwrap().len(), 0);
        drop(index);
        let index = Index::open(dir.path()).unwrap();
        assert_eq!(index.kinds(), &before);
        let e = index.entry("app", "x").unwrap();
        let order: Vec<_> = e.versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(order, ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]);
    }

    #[test]
    fn a_log_replayed_over_its_snapshot_changes_nothing() {
        // As after a crash between renaming the snapshot and emptying the log.
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        index.append(publish("x", "1")).unwrap();
        index.append(channel("1", 1)).unwrap();
        let log = fs::read(dir.path().join("log")).unwrap();
        index.compact().unwrap();
        let before = index.kinds().clone();
        drop(index);
        fs::write(dir.path().join("log"), &log).unwrap();
        let index = Index::open(dir.path()).unwrap();
        assert_eq!(index.kinds(), &before);
    }

    #[test]
    fn the_log_compacts_itself_when_long() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = Index::open(dir.path()).unwrap();
        for v in 0..COMPACT_AFTER {
            index.append(publish("x", &v.to_string())).unwrap();
        }
        assert_eq!(fs::metadata(dir.path().join("log")).unwrap().len(), 0);
        assert!(dir.path().join("snapshot").exists());
    }

    #[test]
    fn an_older_channel_record_does_not_win() {
        let mut kinds = Kinds::new();
        apply(&mut kinds, &channel("2", 2));
        apply(&mut kinds, &channel("1", 1));
        assert_eq!(kinds["app"]["x"].channels["stable"].version, "2");
    }
}
