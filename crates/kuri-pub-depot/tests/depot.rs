//! The depot through Kuri Link, as a client sees it.
//!
//! Every test runs twice: against the depot in this process
//! (`Client::in_process`), and against a depot on a real Kuri Link node over
//! the loopback interface, with relays off. The same service must answer the
//! same way both ways.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use kuri_link::{Allowlist, CallError, Client, FaultCode, Node, NodeKey, Relays, Value};
use kuri_pub::methods::{
    self, GetArgs, HasArgs, KindCount, ListArgs, ListPage, ManifestArgs, ManifestReply,
    PublishArgs, PublishReply, PutArgs, PutResult, SetChannelArgs, SetChannelReply, VersionsArgs,
    VersionsPage,
};
use kuri_pub::{Channel, Code, Digest, Fault, Kind, Manifest, ManifestBuilder, Name, Version};
use kuri_pub_depot::{Depot, DepotService, Settings};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Harness {
    client: Client,
    dir: tempfile::TempDir,
    _nodes: Vec<Node>,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    InProcess,
    Peer,
}

async fn harness(mode: Mode, settings: Settings) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let depot = Arc::new(Depot::open(dir.path(), settings).unwrap());
    match mode {
        Mode::InProcess => Harness {
            client: Client::in_process(DepotService(depot)),
            dir,
            _nodes: Vec::new(),
        },
        Mode::Peer => {
            let key = NodeKey::generate();
            let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let server = Node::builder()
                .relays(Relays::None)
                .bind_addr(loopback)
                .authorizer(Allowlist::new([key.public()]))
                .serve(kuri_pub::APP, DepotService(depot))
                .bind()
                .await
                .unwrap();
            let client_node = Node::builder()
                .secret_key(key)
                .relays(Relays::None)
                .bind_addr(loopback)
                .bind()
                .await
                .unwrap();
            let client = client_node
                .connect(server.bound_addr(), kuri_pub::APP)
                .await
                .unwrap();
            Harness {
                client,
                dir,
                _nodes: vec![server, client_node],
            }
        }
    }
}

fn fault(e: CallError) -> Fault {
    match e {
        CallError::Fault(f) if f.code == FaultCode::App => Fault::parse(&f.message),
        other => panic!("expected a depot's fault, got {other}"),
    }
}

impl Harness {
    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        args: impl Serialize,
    ) -> Result<T, Fault> {
        self.raw(method, Value::serialized(&args).unwrap()).await
    }

    async fn raw<T: DeserializeOwned>(&self, method: &str, args: Value) -> Result<T, Fault> {
        let v = self.client.call(method, args).await.map_err(fault)?;
        Ok(v.deserialized().unwrap())
    }

    /// Uploads `bytes` as announced by `digest` and `size`.
    async fn put_as(&self, digest: &Digest, size: u64, bytes: &[u8]) -> Result<bool, Fault> {
        let args = PutArgs {
            digest: digest.clone(),
            size,
        };
        let mut io = self
            .client
            .open(methods::PUT, Value::serialized(&args).unwrap())
            .await
            .map_err(fault)?;
        // A depot that already holds the blob answers before reading it all;
        // a failed write is then not the outcome, the answer is.
        let _ = io.send.write_all(bytes).await;
        let _ = io.send.shutdown().await;
        let mut answer = Vec::new();
        io.recv.read_to_end(&mut answer).await.unwrap();
        let result: PutResult = ciborium::from_reader(answer.as_slice()).unwrap();
        result.into_result()
    }

    async fn put(&self, bytes: &[u8]) -> Digest {
        let d = Digest::sha256(bytes);
        self.put_as(&d, bytes.len() as u64, bytes).await.unwrap();
        d
    }

    async fn get(&self, digest: &Digest, offset: Option<u64>) -> Result<Vec<u8>, Fault> {
        self.get_raw(
            Value::serialized(&GetArgs {
                digest: digest.clone(),
                offset,
            })
            .unwrap(),
        )
        .await
    }

    async fn get_raw(&self, args: Value) -> Result<Vec<u8>, Fault> {
        let mut io = self.client.open(methods::GET, args).await.map_err(fault)?;
        io.send.shutdown().await.unwrap();
        let mut out = Vec::new();
        io.recv.read_to_end(&mut out).await.unwrap();
        Ok(out)
    }

    async fn publish(&self, m: &Manifest) -> Result<PublishReply, Fault> {
        self.call(
            methods::PUBLISH,
            PublishArgs {
                manifest: m.value().clone(),
            },
        )
        .await
    }

    async fn set_channel(
        &self,
        version: &str,
        expect: Option<u64>,
    ) -> Result<SetChannelReply, Fault> {
        self.call(
            methods::SET_CHANNEL,
            SetChannelArgs {
                kind: kind(),
                name: name(),
                channel: Channel::new("stable").unwrap(),
                version: Version::new(version).unwrap(),
                expect,
            },
        )
        .await
    }

    fn tmp_is_empty(&self) -> bool {
        std::fs::read_dir(self.dir.path().join("tmp"))
            .unwrap()
            .next()
            .is_none()
    }
}

fn kind() -> Kind {
    Kind::new("mod.bg3").unwrap()
}

fn name() -> Name {
    Name::new("Better Camera").unwrap()
}

fn manifest(version: &str, files: &[(&str, &[u8])]) -> Manifest {
    let mut b = ManifestBuilder::new(&kind(), &name(), &Version::new(version).unwrap());
    for (path, bytes) in files {
        b = b.file(path, &Digest::sha256(bytes), bytes.len() as u64);
    }
    b.build().unwrap()
}

/// Publishes `version` with one file whose content is the version itself.
async fn publish_simple(h: &Harness, version: &str) {
    h.put(version.as_bytes()).await;
    let m = manifest(version, &[("mod.pak", version.as_bytes())]);
    assert!(h.publish(&m).await.unwrap().created);
}

macro_rules! both {
    ($($name:ident),* $(,)?) => {
        mod in_process {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { super::$name(super::Mode::InProcess).await })*
        }
        mod peer {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { super::$name(super::Mode::Peer).await })*
        }
    };
}

both!(
    publish_manifest_get_round_trip,
    republishing_the_same_manifest_succeeds_and_other_content_conflicts,
    publish_needs_every_blob_at_its_size,
    get_resumes_from_an_offset,
    get_refusals,
    a_bad_upload_leaves_no_blob,
    a_stored_blob_is_answered_at_once,
    put_refuses_a_blob_over_the_cap,
    channels_move_with_a_position,
    concurrent_moves_of_one_channel_let_one_through,
    pages_follow_their_cursors,
    cursors_are_capped,
    bad_names_are_refused,
    has_answers_in_order_and_is_capped,
    manifest_refusals,
);

async fn publish_manifest_get_round_trip(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let pak = vec![7u8; 300_000];
    let readme = b"read me".to_vec();
    let d_pak = h.put(&pak).await;
    let d_readme = h.put(&readme).await;
    let m = manifest("1.0", &[("mod.pak", &pak), ("docs/README.txt", &readme)]);
    let reply = h.publish(&m).await.unwrap();
    assert!(reply.created);
    assert_eq!(reply.digest.known().unwrap(), *m.digest());

    let got: ManifestReply = h
        .call(
            methods::MANIFEST,
            ManifestArgs {
                kind: kind(),
                name: name(),
                version: Some(Version::new("1.0").unwrap()),
                channel: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(got.version, "1.0");
    assert_eq!(got.digest.known().unwrap(), *m.digest());
    assert_eq!(got.seq, None);
    let back = Manifest::from_value(got.manifest).unwrap();
    assert_eq!(back.digest(), m.digest());
    assert_eq!(h.get(&d_pak, None).await.unwrap(), pak);
    assert_eq!(h.get(&d_readme, None).await.unwrap(), readme);
    // The manifest is a blob like any other.
    assert_eq!(h.get(m.digest(), None).await.unwrap(), m.bytes());

    let kinds: Vec<KindCount> = h.call(methods::KINDS, methods::Empty {}).await.unwrap();
    assert_eq!(
        kinds,
        [KindCount {
            kind: "mod.bg3".into(),
            names: 1
        }]
    );
    let versions: VersionsPage = h
        .call(
            methods::VERSIONS,
            VersionsArgs {
                kind: kind(),
                name: name(),
                after: None,
                limit: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(versions.items.len(), 1);
    assert_eq!(versions.items[0].manifest.known().unwrap(), *m.digest());
    assert!(versions.items[0].published > 0);
}

async fn republishing_the_same_manifest_succeeds_and_other_content_conflicts(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    h.put(b"a").await;
    h.put(b"b").await;
    let first = manifest("1", &[("x", b"a")]);
    assert!(h.publish(&first).await.unwrap().created);
    let again = h.publish(&first).await.unwrap();
    assert!(!again.created);
    assert_eq!(again.digest.known().unwrap(), *first.digest());

    let other = manifest("1", &[("x", b"b")]);
    let f = h.publish(&other).await.unwrap_err();
    assert_eq!(f.code, Code::Conflict);
    assert_eq!(f.detail, format!("stored {}", first.digest()));
    // A new `created` is new content: a retry must resend the same manifest.
    let late = ManifestBuilder::new(&kind(), &name(), &Version::new("1").unwrap())
        .file("x", &Digest::sha256(b"a"), 1)
        .created(5)
        .build()
        .unwrap();
    assert_eq!(h.publish(&late).await.unwrap_err().code, Code::Conflict);
}

async fn publish_needs_every_blob_at_its_size(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let m = manifest("1", &[("x", b"absent")]);
    assert_eq!(h.publish(&m).await.unwrap_err().code, Code::MissingBlobs);
    // Stored, but not the size the manifest claims.
    h.put(b"abc").await;
    let wrong = ManifestBuilder::new(&kind(), &name(), &Version::new("1").unwrap())
        .file("x", &Digest::sha256(b"abc"), 4)
        .build()
        .unwrap();
    assert_eq!(
        h.publish(&wrong).await.unwrap_err().code,
        Code::MissingBlobs
    );
    let bad = map(&[("manifest", map(&[("format", Value::Integer(1.into()))]))]);
    let f = h.raw::<Value>(methods::PUBLISH, bad).await.unwrap_err();
    assert_eq!(f.code, Code::BadManifest);
    let f = h
        .raw::<Value>(methods::PUBLISH, map(&[]))
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::BadManifest);
}

async fn get_resumes_from_an_offset(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let d = h.put(&bytes).await;
    let mut got = h.get(&d, None).await.unwrap();
    got.truncate(70_001);
    got.extend(h.get(&d, Some(70_001)).await.unwrap());
    assert_eq!(got, bytes);
    assert_eq!(Digest::sha256(&got), d);
    assert!(
        h.get(&d, Some(bytes.len() as u64))
            .await
            .unwrap()
            .is_empty()
    );
}

async fn get_refusals(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let d = h.put(b"four").await;
    assert_eq!(h.get(&d, Some(5)).await.unwrap_err().code, Code::BadRange);
    let absent = Digest::sha256(b"absent");
    assert_eq!(h.get(&absent, None).await.unwrap_err().code, Code::NotFound);
    let merkle = map(&[("digest", digest_wire("merkle", &"0".repeat(64)))]);
    assert_eq!(
        h.get_raw(merkle).await.unwrap_err().code,
        Code::UnsupportedAlg
    );
    let short = map(&[("digest", digest_wire("sha256", "00"))]);
    assert_eq!(h.get_raw(short).await.unwrap_err().code, Code::BadName);
}

async fn a_bad_upload_leaves_no_blob(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let claimed = Digest::sha256(b"what was promised");
    let f = h.put_as(&claimed, 4, b"else").await.unwrap_err();
    assert_eq!(f.code, Code::DigestMismatch);
    let d = Digest::sha256(b"exact");
    let f = h.put_as(&d, 5, b"exa").await.unwrap_err();
    assert_eq!(f.code, Code::SizeMismatch);
    let f = h.put_as(&d, 5, b"exact and more").await.unwrap_err();
    assert_eq!(f.code, Code::SizeMismatch);
    // Refused as soon as it passes the size announced, not after reading
    // whatever the client sends.
    assert!(f.detail.starts_with("more than"), "{}", f.detail);
    let has: Vec<bool> = h
        .call(
            methods::HAS,
            HasArgs {
                digests: vec![claimed, d.clone()],
            },
        )
        .await
        .unwrap();
    assert_eq!(has, [false, false]);
    assert!(
        !h.dir
            .path()
            .join("blobs/sha256")
            .join(&d.hex()[..2])
            .join(d.hex())
            .exists()
    );
    // The temporary files went with them.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(h.tmp_is_empty());
    // And the right bytes still go in afterwards.
    assert!(h.put_as(&d, 5, b"exact").await.unwrap());
}

async fn a_stored_blob_is_answered_at_once(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let big = vec![1u8; 2 << 20];
    let d = Digest::sha256(&big);
    assert!(h.put_as(&d, big.len() as u64, &big).await.unwrap());
    // The second upload is answered `stored: false`, whatever the client
    // still sends; the depot does not read it.
    assert!(!h.put_as(&d, big.len() as u64, &big).await.unwrap());
    assert!(h.tmp_is_empty());
}

async fn put_refuses_a_blob_over_the_cap(mode: Mode) {
    let h = harness(mode, Settings { max_blob: 10 }).await;
    assert!(
        h.put_as(&Digest::sha256(&[0; 10]), 10, &[0; 10])
            .await
            .unwrap()
    );
    let args = PutArgs {
        digest: Digest::sha256(&[0; 11]),
        size: 11,
    };
    let e = h
        .client
        .open(methods::PUT, Value::serialized(&args).unwrap())
        .await
        .unwrap_err();
    assert_eq!(fault(e).code, Code::TooLarge);
    let merkle = map(&[
        ("digest", digest_wire("merkle", &"0".repeat(64))),
        ("size", Value::Integer(1.into())),
    ]);
    let e = h.client.open(methods::PUT, merkle).await.unwrap_err();
    assert_eq!(fault(e).code, Code::UnsupportedAlg);
}

async fn channels_move_with_a_position(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    publish_simple(&h, "1").await;
    publish_simple(&h, "2").await;
    let r = h.set_channel("1", Some(0)).await.unwrap();
    assert_eq!((r.previous, r.seq), (None, 1));
    let r = h.set_channel("2", None).await.unwrap();
    assert_eq!((r.previous.as_deref(), r.seq), (Some("1"), 2));
    // Rolling back is a move like any other, and the position still grows.
    let r = h.set_channel("1", Some(2)).await.unwrap();
    assert_eq!((r.previous.as_deref(), r.seq), (Some("2"), 3));
    let f = h.set_channel("2", Some(2)).await.unwrap_err();
    assert_eq!(f.code, Code::ChannelMoved);
    let f = h.set_channel("2", Some(0)).await.unwrap_err();
    assert_eq!(f.code, Code::ChannelMoved);
    assert_eq!(
        h.set_channel("9", None).await.unwrap_err().code,
        Code::NotFound
    );

    let by_channel: ManifestReply = h
        .call(
            methods::MANIFEST,
            ManifestArgs {
                kind: kind(),
                name: name(),
                version: None,
                channel: Some(Channel::new("stable").unwrap()),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        (by_channel.version.as_str(), by_channel.seq),
        ("1", Some(3))
    );
    let page: ListPage = h
        .call(
            methods::LIST,
            ListArgs {
                kind: kind(),
                after: None,
                limit: None,
            },
        )
        .await
        .unwrap();
    let pointer = &page.items[0].channels["stable"];
    assert_eq!((pointer.version.as_str(), pointer.seq), ("1", 3));
    assert_eq!(page.items[0].versions, 2);
}

async fn concurrent_moves_of_one_channel_let_one_through(mode: Mode) {
    let h = Arc::new(harness(mode, Settings::default()).await);
    for v in ["1", "2", "3", "4", "5", "6"] {
        publish_simple(&h, v).await;
    }
    h.set_channel("1", Some(0)).await.unwrap();
    let moves = ["2", "3", "4", "5", "6"].map(|v| {
        let h = h.clone();
        tokio::spawn(async move { h.set_channel(v, Some(1)).await })
    });
    let mut won = 0;
    for m in moves {
        match m.await.unwrap() {
            Ok(r) => {
                won += 1;
                assert_eq!(r.seq, 2);
            }
            Err(f) => assert_eq!(f.code, Code::ChannelMoved),
        }
    }
    assert_eq!(won, 1);
}

async fn pages_follow_their_cursors(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let names = ["b", "a", "C", "é", "aa"];
    for n in names {
        h.put(n.as_bytes()).await;
        let m = ManifestBuilder::new(&kind(), &Name::new(n).unwrap(), &Version::new("1").unwrap())
            .file("f", &Digest::sha256(n.as_bytes()), n.len() as u64)
            .build()
            .unwrap();
        h.publish(&m).await.unwrap();
    }
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page: ListPage = h
            .call(
                methods::LIST,
                ListArgs {
                    kind: kind(),
                    after: after.clone(),
                    limit: Some(2),
                },
            )
            .await
            .unwrap();
        seen.extend(page.items.iter().map(|i| i.name.clone()));
        match page.next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    // Bytewise: upper case before lower, "a" before "aa", "é" last.
    assert_eq!(seen, ["C", "a", "aa", "b", "é"]);
    let empty: ListPage = h
        .call(
            methods::LIST,
            ListArgs {
                kind: Kind::new("app").unwrap(),
                after: None,
                limit: None,
            },
        )
        .await
        .unwrap();
    assert!(empty.items.is_empty() && empty.next.is_none());

    for v in ["3", "1", "2"] {
        publish_simple(&h, v).await;
    }
    let mut order = Vec::new();
    let mut after = None;
    loop {
        let page: VersionsPage = h
            .call(
                methods::VERSIONS,
                VersionsArgs {
                    kind: kind(),
                    name: name(),
                    after: after.clone(),
                    limit: Some(1),
                },
            )
            .await
            .unwrap();
        order.extend(page.items.iter().map(|i| i.version.clone()));
        match page.next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    // Publish order, not any order of the versions themselves.
    assert_eq!(order, ["3", "1", "2"]);
    let f = h
        .call::<VersionsPage>(
            methods::VERSIONS,
            VersionsArgs {
                kind: kind(),
                name: name(),
                after: Some("9".into()),
                limit: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::NotFound);
    let f = h
        .call::<VersionsPage>(
            methods::VERSIONS,
            VersionsArgs {
                kind: kind(),
                name: Name::new("nobody").unwrap(),
                after: None,
                limit: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::NotFound);
}

async fn cursors_are_capped(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    publish_simple(&h, "1").await;
    let list = |after: String| ListArgs {
        kind: kind(),
        after: Some(after),
        limit: None,
    };
    h.call::<ListPage>(methods::LIST, list("x".repeat(128)))
        .await
        .unwrap();
    let f = h
        .call::<ListPage>(methods::LIST, list("x".repeat(129)))
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::BadName);
    let versions = |after: String| VersionsArgs {
        kind: kind(),
        name: name(),
        after: Some(after),
        limit: None,
    };
    // At the cap the cursor is read (and names no version); over it, refused.
    let f = h
        .call::<VersionsPage>(methods::VERSIONS, versions("x".repeat(64)))
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::NotFound);
    let f = h
        .call::<VersionsPage>(methods::VERSIONS, versions("x".repeat(65)))
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::BadName);
}

async fn bad_names_are_refused(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let f = h
        .raw::<Value>(methods::LIST, map(&[("kind", Value::Text("App".into()))]))
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::BadName);
    let f = h
        .raw::<Value>(
            methods::VERSIONS,
            map(&[
                ("kind", Value::Text("app".into())),
                ("name", Value::Text("CON".into())),
            ]),
        )
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::BadName);
    let e = h.client.call("delete", map(&[])).await.unwrap_err();
    match e {
        CallError::Fault(f) => assert_eq!(f.code, FaultCode::NoSuchMethod),
        other => panic!("{other}"),
    }
}

async fn has_answers_in_order_and_is_capped(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    let a = h.put(b"a").await;
    let b = Digest::sha256(b"b");
    let has: Vec<bool> = h
        .call(
            methods::HAS,
            HasArgs {
                digests: vec![b.clone(), a.clone(), b.clone()],
            },
        )
        .await
        .unwrap();
    assert_eq!(has, [false, true, false]);
    let f = h
        .call::<Vec<bool>>(
            methods::HAS,
            HasArgs {
                digests: vec![a; methods::MAX_HAS + 1],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(f.code, Code::TooLarge);
    let merkle = map(&[(
        "digests",
        Value::Array(vec![digest_wire("merkle", &"0".repeat(64))]),
    )]);
    let f = h.raw::<Vec<bool>>(methods::HAS, merkle).await.unwrap_err();
    assert_eq!(f.code, Code::UnsupportedAlg);
}

async fn manifest_refusals(mode: Mode) {
    let h = harness(mode, Settings::default()).await;
    publish_simple(&h, "1").await;
    let ask = |version: Option<&str>, channel: Option<&str>| ManifestArgs {
        kind: kind(),
        name: name(),
        version: version.map(|v| Version::new(v).unwrap()),
        channel: channel.map(|c| Channel::new(c).unwrap()),
    };
    for (args, code) in [
        (ask(Some("2"), None), Code::NotFound),
        (ask(None, Some("stable")), Code::NotFound),
        (ask(Some("1"), Some("stable")), Code::BadName),
        (ask(None, None), Code::BadName),
    ] {
        let f = h
            .call::<ManifestReply>(methods::MANIFEST, args)
            .await
            .unwrap_err();
        assert_eq!(f.code, code);
    }
}

/// What a crash leaves: the depot reopens on a log whose last record is torn,
/// keeps everything before it, and takes the lost publish again.
#[tokio::test(flavor = "multi_thread")]
async fn a_torn_index_record_is_dropped_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let open = |dir: &Path| Arc::new(Depot::open(dir, Settings::default()).unwrap());
    let h = Harness {
        client: Client::in_process(DepotService(open(dir.path()))),
        dir,
        _nodes: Vec::new(),
    };
    publish_simple(&h, "1").await;
    publish_simple(&h, "2").await;
    let Harness { client, dir, .. } = h;
    drop(client);
    let log = dir.path().join("index/log");
    let len = std::fs::metadata(&log).unwrap().len();
    std::fs::File::options()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(len - 3)
        .unwrap();
    let h = Harness {
        client: Client::in_process(DepotService(open(dir.path()))),
        dir,
        _nodes: Vec::new(),
    };
    let page: VersionsPage = h
        .call(
            methods::VERSIONS,
            VersionsArgs {
                kind: kind(),
                name: name(),
                after: None,
                limit: None,
            },
        )
        .await
        .unwrap();
    let versions: Vec<_> = page.items.iter().map(|i| i.version.as_str()).collect();
    assert_eq!(versions, ["1"]);
    let m = manifest("2", &[("mod.pak", b"2")]);
    assert!(h.publish(&m).await.unwrap().created);
}

fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| (Value::Text((*k).into()), v.clone()))
            .collect(),
    )
}

fn digest_wire(alg: &str, hex: &str) -> Value {
    map(&[
        ("alg", Value::Text(alg.into())),
        ("hex", Value::Text(hex.into())),
    ])
}
