//! Blobs on disk, named by their digest.
//!
//! ```text
//! <store>/blobs/sha256/ab/abcdef…   content, read-only once renamed
//! <store>/tmp/                       uploads in progress; emptied at start
//! ```
//!
//! A blob appears under its name only once it is complete and on disk: it is
//! written to a file in `tmp/`, synced, renamed into place, and the directory
//! it landed in is synced. A crash leaves at most a file in `tmp/`, which the
//! next start removes, never a partial blob under a real name. `tmp/` is inside
//! the store so the rename never crosses a filesystem.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kuri_pub::Digest;

/// The blob directory of a store.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    next_tmp: AtomicU64,
}

impl Store {
    /// Opens the store at `root`, creating its directories, and removes what
    /// an earlier run left in `tmp/`.
    pub fn open(root: &Path) -> io::Result<Store> {
        fs::create_dir_all(root.join("blobs"))?;
        let tmp = root.join("tmp");
        if tmp.exists() {
            fs::remove_dir_all(&tmp)?;
        }
        fs::create_dir_all(&tmp)?;
        sync_dir(root)?;
        Ok(Store {
            root: root.to_owned(),
            next_tmp: AtomicU64::new(0),
        })
    }

    /// Where blob `digest` lives.
    pub fn path(&self, digest: &Digest) -> PathBuf {
        let hex = digest.hex();
        self.root
            .join("blobs")
            .join(digest.alg().as_str())
            .join(&hex[..2])
            .join(hex)
    }

    /// The blob's size, or `None` if the store does not hold it.
    pub fn size(&self, digest: &Digest) -> io::Result<Option<u64>> {
        match fs::metadata(self.path(digest)) {
            Ok(m) => Ok(Some(m.len())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// A new, empty file in `tmp/` and its path. Each call names a new one.
    pub fn temporary(&self) -> io::Result<(PathBuf, File)> {
        let n = self.next_tmp.fetch_add(1, Ordering::Relaxed);
        let path = self
            .root
            .join("tmp")
            .join(format!("{}-{n}", std::process::id()));
        let file = File::options().write(true).create_new(true).open(&path)?;
        Ok((path, file))
    }

    /// Makes the complete file at `tmp` the blob `digest`: syncs it, renames
    /// it into place, and syncs the directory it landed in. The caller has
    /// checked that its content hashes to `digest`.
    pub fn commit(&self, tmp: &Path, file: File, digest: &Digest) -> io::Result<()> {
        file.sync_all()?;
        drop(file);
        let dest = self.path(digest);
        let dir = dest.parent().expect("a blob path has a directory");
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            // The new directories must survive a crash too, or the rename
            // into them could be lost with them.
            sync_dir(dir.parent().expect("under blobs/<alg>"))?;
            sync_dir(&self.root.join("blobs"))?;
        }
        fs::rename(tmp, &dest)?;
        sync_dir(dir)
    }

    /// Stores `bytes` as blob `digest`, unless it is already there.
    pub fn put_bytes(&self, digest: &Digest, bytes: &[u8]) -> io::Result<()> {
        if self.size(digest)?.is_some() {
            return Ok(());
        }
        let (path, mut file) = self.temporary()?;
        let result = file
            .write_all(bytes)
            .and_then(|()| self.commit(&path, file, digest));
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        result
    }

    /// The blob's content, whole. For manifests, which are small.
    pub fn read(&self, digest: &Digest) -> io::Result<Vec<u8>> {
        fs::read(self.path(digest))
    }
}

/// Syncs a directory, so the names created or renamed in it are on disk.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_lands_under_its_digest() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let d = Digest::sha256(b"hello");
        assert_eq!(store.size(&d).unwrap(), None);
        store.put_bytes(&d, b"hello").unwrap();
        assert_eq!(store.size(&d).unwrap(), Some(5));
        let hex = d.hex();
        assert_eq!(
            store.path(&d),
            dir.path().join("blobs/sha256").join(&hex[..2]).join(hex)
        );
        assert_eq!(store.read(&d).unwrap(), b"hello");
    }

    #[test]
    fn opening_empties_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (path, _file) = store.temporary().unwrap();
        assert!(path.exists());
        drop(store);
        Store::open(dir.path()).unwrap();
        assert!(!path.exists());
        assert!(dir.path().join("tmp").is_dir());
    }

    #[test]
    fn temporary_files_have_distinct_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (a, _) = store.temporary().unwrap();
        let (b, _) = store.temporary().unwrap();
        assert_ne!(a, b);
    }
}
