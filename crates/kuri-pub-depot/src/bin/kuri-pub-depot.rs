//! A depot on its own: keeps a store directory and serves it as the Kuri Link
//! app `pub`.
//!
//! ```text
//! kuri-pub-depot --store DIR [--max-blob BYTES]
//!                [--port PORT | --bind ADDR] [--port-mapping]
//!                [--peers FILE] [--key FILE] [--relay URL]...
//! kuri-pub-depot --store DIR [--max-blob BYTES]
//!                --gateway FILE [--gateway-ticket TICKET] [--key FILE]
//! ```
//!
//! `--store DIR` holds the blobs and the index; it is created if it is new.
//! `--max-blob` caps one blob, 64 GiB unless given.
//!
//! Listening, it prints a pairing ticket on one line, for one device within
//! ten minutes, and serves the devices that redeem one. The flags are those of
//! Kuri Link's example server: `--port` or `--bind` choose where it listens,
//! `--port-mapping` asks the router to forward the port, `--peers` keeps the
//! paired devices across restarts and `--key` the depot's own key, `--relay`
//! names a relay to stay reachable through.
//!
//! With `--gateway`, it listens for nothing and serves through a home's
//! gateway, which pairs the devices. FILE holds the gateway's address; the
//! first time, pass `--gateway-ticket` with a back-end ticket from the
//! gateway, and keep `--key`, or the gateway sees a stranger after a restart.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kuri_link::{
    Node, NodeBuilder, Pairing, PeerAddr, PeerSet, Reach, Registration, RelayUrl, Relays, Ticket,
};
use kuri_pub_depot::{Depot, DepotService, Settings};

const TICKET_TTL: Duration = Duration::from_secs(10 * 60);

/// How long to wait for the router to forward the port.
const MAPPING_WAIT: Duration = Duration::from_secs(5);

const CLOSED: &str = "the network endpoint closed by itself, as it does when the \
                      --bind address goes away and there is no --relay";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kuri-pub-depot: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut store: Option<PathBuf> = None;
    let mut settings = Settings::default();
    let mut bind: Option<SocketAddr> = None;
    let mut port = None;
    let mut port_mapping = false;
    let mut peers = None;
    let mut key = None;
    let mut gateway: Option<PathBuf> = None;
    let mut gateway_ticket: Option<Ticket> = None;
    let mut relays: Vec<RelayUrl> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--store" => store = Some(value()?.into()),
            "--max-blob" => {
                settings.max_blob = value()?.parse().map_err(|e| format!("--max-blob: {e}"))?
            }
            "--bind" => bind = Some(value()?.parse().map_err(|e| format!("--bind: {e}"))?),
            "--port" => port = Some(value()?.parse().map_err(|e| format!("--port: {e}"))?),
            "--port-mapping" => port_mapping = true,
            "--peers" => {
                peers = Some(PeerSet::open(value()?).map_err(|e| format!("--peers: {e}"))?)
            }
            "--key" => {
                let path = value()?;
                key = Some(
                    kuri_link::load_or_create_key(path.as_ref())
                        .map_err(|e| format!("--key: {e}"))?,
                );
            }
            "--relay" => relays.push(value()?.parse().map_err(|e| format!("--relay: {e}"))?),
            "--gateway" => gateway = Some(value()?.into()),
            "--gateway-ticket" => {
                gateway_ticket = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--gateway-ticket: {e}"))?,
                )
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let store = store.ok_or("--store DIR is required: where the blobs and the index live")?;
    let depot =
        Depot::open(&store, settings).map_err(|e| format!("--store {}: {e}", store.display()))?;

    let mut builder = Node::builder()
        .relays(if relays.is_empty() {
            Relays::None
        } else {
            Relays::Custom(relays.clone())
        })
        .local_discovery(true)
        .serve(kuri_pub::APP, DepotService(Arc::new(depot)));
    if let Some(key) = key {
        builder = builder.secret_key(key);
    }
    if let Some(file) = gateway {
        if peers.is_some() || port_mapping || bind.is_some() || port.is_some() {
            return Err(
                "behind a gateway, the gateway pairs the devices and faces outside; \
                 --peers, --port-mapping, --bind and --port are for a depot that listens"
                    .into(),
            );
        }
        return behind(builder, &file, gateway_ticket).await;
    }
    if gateway_ticket.is_some() {
        return Err(
            "--gateway-ticket needs --gateway FILE, to keep the gateway's address in".into(),
        );
    }
    let pairing = Pairing::new(peers.unwrap_or_default());
    builder = builder.port_mapping(port_mapping).pairing(pairing.clone());
    match (bind, port) {
        (Some(_), Some(_)) => return Err("--bind and --port both name a port; pass one".into()),
        (Some(addr), None) => builder = builder.bind_addr(addr),
        (None, Some(port)) => builder = builder.port(port),
        (None, None) => {}
    }
    let node = builder.bind().await.map_err(|e| e.to_string())?;
    let reach = node.reach(MAPPING_WAIT).await;

    // A socket bound to every interface names no address a peer can dial;
    // the addresses found on those interfaces do.
    let mut addr = node.bound_addr();
    if addr.addrs.is_empty() {
        addr = node.addr();
    }
    if let Reach::Public(outside) | Reach::BehindNat(outside) = reach {
        addr = addr.with_addr(outside);
    }
    // The relays go in as given: the connection to them may not be up yet.
    for relay in relays {
        addr = addr.with_relay(relay);
    }
    if addr.addrs.is_empty() && addr.relays.is_empty() {
        return Err(
            "no address to put in the ticket; pass --bind with this host's address, or --relay"
                .into(),
        );
    }

    // One line, so a script or a test can read it.
    println!("{}", pairing.issue(addr, TICKET_TTL));
    eprintln!(
        "serving {} from {} as {}; the ticket above pairs one device and expires in {} minutes",
        kuri_pub::APP,
        store.display(),
        node.id().fmt_short(),
        TICKET_TTL.as_secs() / 60,
    );
    let closed = node.closed();
    let result = tokio::select! {
        () = stopped() => Ok(()),
        () = closed => Err(CLOSED.to_owned()),
    };
    node.shutdown().await;
    result
}

/// Finishes when the depot is told to stop: Ctrl-C, or SIGTERM from a
/// supervisor.
async fn stopped() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Serves through the gateway whose address `file` holds, pairing with it
/// first if given a ticket.
async fn behind(builder: NodeBuilder, file: &Path, ticket: Option<Ticket>) -> Result<(), String> {
    let gateway: PeerAddr = match &ticket {
        Some(ticket) => ticket.addr.clone(),
        None => std::fs::read_to_string(file)
            .map_err(|e| {
                format!(
                    "--gateway {}: {e}; pair with the gateway first (--gateway-ticket)",
                    file.display()
                )
            })?
            .parse()
            .map_err(|e| format!("--gateway {}: {e}", file.display()))?,
    };
    let node = builder
        .behind_gateway(gateway.clone())
        .bind()
        .await
        .map_err(|e| e.to_string())?;
    let keep = |addr: &PeerAddr| {
        std::fs::write(file, format!("{addr}\n")).map_err(|e| format!("{}: {e}", file.display()))
    };
    if let Some(ticket) = ticket {
        let gateway = node
            .pair_gateway(&ticket)
            .await
            .map_err(|e| format!("pairing with the gateway: {e}"))?;
        keep(&gateway)?;
    }
    eprintln!(
        "serving {} as {} through the gateway {}",
        kuri_pub::APP,
        node.id().fmt_short(),
        gateway.id.fmt_short(),
    );
    let mut addr = node.gateway_addr().expect("behind a gateway");
    let mut registration = node.registration().expect("behind a gateway");
    let stop = stopped();
    tokio::pin!(stop);
    let closed = node.closed();
    tokio::pin!(closed);
    let result = loop {
        tokio::select! {
            _ = &mut stop => break Ok(()),
            () = &mut closed => break Err(CLOSED.to_owned()),
            changed = addr.changed() => {
                if changed.is_err() {
                    break Ok(());
                }
                let now = addr.borrow_and_update().clone();
                keep(&now)?;
                eprintln!("the gateway is now at {now}");
            }
            changed = registration.changed() => {
                if changed.is_err() {
                    break Ok(());
                }
                let now = registration.borrow_and_update().clone();
                eprintln!("{}", registered(&now));
            }
        }
    };
    node.shutdown().await;
    result
}

fn registered(registration: &Registration) -> String {
    match registration {
        Registration::Registered => {
            "registered with the gateway: devices paired with it reach this depot".into()
        }
        Registration::Refused(fault) => format!("the gateway refused this depot: {fault}"),
        _ => "not connected to the gateway; dialing it again".into(),
    }
}
