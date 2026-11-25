//! Uploads a blob of N bytes to a depot and reads it back, to measure.
//!
//! ```text
//! cargo run --release --example transfer -- TICKET BYTES
//! ```
//!
//! Pairs with the depot by its ticket, `put`s BYTES of generated content,
//! `get`s it back, checks the digest, and prints the rate of each. The content
//! is generated twice (once to hash it, once to send it), so the client's
//! memory does not grow with BYTES either.

use std::str::FromStr;
use std::time::Instant;

use kuri_link::{Node, Relays, Ticket, Value};
use kuri_pub::Digest;
use kuri_pub::methods::{self, GetArgs, PutArgs, PutResult};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: usize = 64 * 1024;

/// The `i`th chunk of the content: not all zeros, so nothing on the way can
/// compress it away.
fn chunk(i: u64, buf: &mut [u8]) {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
}

fn chunks(size: u64) -> impl Iterator<Item = (u64, usize)> {
    let n = size.div_ceil(CHUNK as u64);
    (0..n).map(move |i| (i, (size - i * CHUNK as u64).min(CHUNK as u64) as usize))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let ticket = Ticket::from_str(args.next().ok_or("TICKET BYTES")?.trim())?;
    let size: u64 = args.next().ok_or("TICKET BYTES")?.parse()?;

    let mut buf = vec![0u8; CHUNK];
    let mut hasher = Sha256::new();
    for (i, n) in chunks(size) {
        chunk(i, &mut buf[..n]);
        hasher.update(&buf[..n]);
    }
    let digest = Digest::from_sha256(hasher.finalize().into());

    let relays: Vec<_> = ticket.addr.relays.iter().cloned().collect();
    let node = Node::builder()
        .relays(if relays.is_empty() {
            Relays::None
        } else {
            Relays::Custom(relays)
        })
        .bind()
        .await?;
    let addr = node.pair(&ticket).await?;
    let client = node.connect(addr, kuri_pub::APP).await?;

    let start = Instant::now();
    let args = PutArgs {
        digest: digest.clone(),
        size,
    };
    let mut io = client.open(methods::PUT, Value::serialized(&args)?).await?;
    for (i, n) in chunks(size) {
        chunk(i, &mut buf[..n]);
        if io.send.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = io.send.shutdown().await;
    let mut answer = Vec::new();
    io.recv.read_to_end(&mut answer).await?;
    let stored = ciborium::from_reader::<PutResult, _>(answer.as_slice())?.into_result()?;
    let secs = start.elapsed().as_secs_f64();
    println!(
        "put {size} bytes (stored: {stored}) in {secs:.2} s = {:.1} MiB/s",
        size as f64 / 1048576.0 / secs
    );

    let start = Instant::now();
    let args = GetArgs {
        digest: digest.clone(),
        offset: None,
    };
    let mut io = client.open(methods::GET, Value::serialized(&args)?).await?;
    io.send.shutdown().await?;
    let mut hasher = Sha256::new();
    let mut got = 0u64;
    loop {
        let n = io.recv.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        got += n as u64;
    }
    let back = Digest::from_sha256(hasher.finalize().into());
    let secs = start.elapsed().as_secs_f64();
    println!(
        "get {got} bytes in {secs:.2} s = {:.1} MiB/s, digest {}",
        got as f64 / 1048576.0 / secs,
        if back == digest { "matches" } else { "DIFFERS" }
    );
    node.shutdown().await;
    Ok(())
}
