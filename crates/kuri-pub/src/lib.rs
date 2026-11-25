//! The contract of a kuri-pub depot: the names, manifests, digests, methods
//! and faults that a depot and its clients share.
//!
//! A depot keeps every version of what a home installs. Content lives in
//! blobs named by their digest; a version is a manifest that maps paths to
//! blobs, named by `(kind, name, version)` and identified by the digest of its
//! canonical encoding; a channel is a movable pointer to a version. A depot
//! serves all of it as the Kuri Link app [`APP`].
//!
//! This crate is the contract alone: no I/O, no networking, no storage. It
//! builds for every target a client runs on; CI checks a browser's
//! WebAssembly (`wasm32-unknown-unknown`) and 32-bit ARM
//! (`armv7-unknown-linux-musleabihf`) besides the host.
//!
//! Requests are checked as they are read; replies are read as the depot wrote
//! them, so that loosening a rule later does not break older clients. See
//! [`methods`].
//!
//! The tables of methods and of manifest keys only grow once released: a
//! reader ignores what it does not know, and a depot keeps it.
//!
//! Not part of the contract yet, and kept open for:
//! - **signatures**, which will sign index entries and channel pointers
//!   (`(kind, name, version) → digest`, and a channel's version with its
//!   `seq`), never a manifest, whose digest would have to cover itself;
//! - **a second digest algorithm**, Fuchsia's Merkle root, see [`Alg`];
//! - **lists** of versions fetched together, as a manifest of their own kind;
//! - **deleting** anything: no version is removed or replaced.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cbor;
pub mod digest;
pub mod fault;
pub mod manifest;
pub mod methods;
pub mod names;

pub use digest::{Alg, Digest, ReportedDigest};
pub use fault::{Code, Fault};
pub use manifest::{Dep, File, Manifest, ManifestBuilder, Origin, Target};
pub use methods::APP;
pub use names::{Channel, Kind, Name, Version};
