//! A kuri-pub depot: keeps blobs and versions in a directory and serves them
//! as the Kuri Link app `pub`, as the contract in the crate `kuri-pub` says.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use kuri_pub_depot::{Depot, DepotService, Settings};
//!
//! let depot = Depot::open("store".as_ref(), Settings::default())?;
//! let node = kuri_link::Node::builder()
//!     .serve(kuri_pub::APP, DepotService(Arc::new(depot)))
//!     .bind()
//!     .await?;
//! # drop(node); Ok(()) }
//! ```
//!
//! Its memory does not grow with a blob's size: `put` streams through a fixed
//! buffer into a temporary file and `get` reads a fixed chunk at a time. What
//! it keeps in memory is the index, names and digests.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod depot;
pub mod index;
pub mod store;

pub use depot::{Depot, DepotService, Settings};
