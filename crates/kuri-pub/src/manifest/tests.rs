use super::*;

// Vectors written by an encoder independent of this crate (`vectors/gen.py`):
// `a` is the smallest manifest; `b` uses every field and has unknown keys at
// the top, inside a file and nested; `bloose` is `b` with every integer and
// length in eight bytes and every map's keys reversed.
const A: &str = include_str!("vectors/a.cbor.hex");
const A_SHA256: &str = include_str!("vectors/a.sha256");
const B: &str = include_str!("vectors/b.cbor.hex");
const B_SHA256: &str = include_str!("vectors/b.sha256");
const B_LOOSE: &str = include_str!("vectors/bloose.cbor.hex");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (t(k), v)).collect())
}

fn hello() -> Digest {
    Digest::sha256(b"hello")
}

fn builder() -> ManifestBuilder {
    ManifestBuilder::new(
        &Kind::new("app").unwrap(),
        &Name::new("hello").unwrap(),
        &Version::new("1.0").unwrap(),
    )
}

fn file(path: &str) -> Value {
    map(vec![
        ("path", t(path)),
        ("digest", Value::serialized(&hello()).unwrap()),
        ("size", Value::Integer(5.into())),
    ])
}

/// A valid manifest as a value, with `key` replaced by `value` (or removed
/// when `value` is `None`).
fn with(key: &str, value: Option<Value>) -> Value {
    let mut entries = vec![
        ("format", Value::Integer(1.into())),
        ("kind", t("app")),
        ("name", t("hello")),
        ("version", t("1.0")),
        ("files", Value::Array(vec![file("hello.exe")])),
    ];
    entries.retain(|(k, _)| *k != key);
    if let Some(v) = value {
        entries.push((key, v));
    }
    map(entries)
}

fn refused(v: Value) -> Fault {
    Manifest::from_value(v).unwrap_err()
}

#[test]
fn smallest_manifest_matches_its_vector() {
    let m = builder().file("hello.exe", &hello(), 5).build().unwrap();
    assert_eq!(m.bytes(), unhex(A));
    assert_eq!(m.digest().hex(), A_SHA256);
    assert_eq!(Manifest::decode(&unhex(A)).unwrap(), m);
}

#[test]
fn unknown_keys_are_kept_and_covered_by_the_digest() {
    let m = Manifest::decode(&unhex(B)).unwrap();
    assert_eq!(m.bytes(), unhex(B));
    assert_eq!(m.digest().hex(), B_SHA256);
    assert_eq!(m.kind().as_str(), "mod.bg3");
    assert_eq!(m.version().as_str(), "2.1-été");
    assert_eq!(m.files().len(), 2);
    assert_eq!(m.meta()["game"], "bg3");
    assert_eq!(m.target().unwrap().os, "windows");
    assert_eq!(m.deps()[0].name.as_str(), "Script Extender");
    assert_eq!(m.origin(), Some(Origin::Upload));
    assert_eq!(m.created(), Some(1_764_054_000_000));
    let top = fields(m.value(), "manifest").unwrap();
    assert!(top.contains_key("x-future"));
}

#[test]
fn any_encoding_of_one_manifest_has_one_digest() {
    let m = Manifest::decode(&unhex(B_LOOSE)).unwrap();
    assert_eq!(m.bytes(), unhex(B));
    assert_eq!(m.digest().hex(), B_SHA256);
}

#[test]
fn every_field_through_the_builder() {
    let deps = [Dep {
        kind: Kind::new("mod.bg3").unwrap(),
        name: Name::new("Script Extender").unwrap(),
        req: ">=1".into(),
    }];
    let m = ManifestBuilder::new(
        &Kind::new("mod.bg3").unwrap(),
        &Name::new("Better Camp").unwrap(),
        &Version::new("2.1-été").unwrap(),
    )
    .file("Mods/BetterCamp.pak", &hello(), 5)
    .file("README.txt", &Digest::sha256(b""), 0)
    .meta([("game", "bg3"), ("title", "Better Camp")])
    .target("windows", "x86_64")
    .deps(&deps)
    .origin(Origin::Upload)
    .created(1_764_054_000_000)
    .build()
    .unwrap();
    // The vector also has unknown keys; everything else is the same.
    let b = Manifest::decode(&unhex(B)).unwrap();
    assert_eq!(m.meta(), b.meta());
    assert_eq!(m.target(), b.target());
    assert_eq!(m.deps(), b.deps());
    assert_ne!(m.digest(), b.digest());
}

#[test]
fn the_received_size_is_capped() {
    let mut bytes = unhex(A);
    bytes.resize(MAX_MANIFEST + 1, 0);
    assert_eq!(Manifest::decode(&bytes).unwrap_err().code, Code::TooLarge);
}

#[test]
fn the_encoded_size_is_capped() {
    let big = "x".repeat(MAX_MANIFEST);
    let err = builder()
        .file("a", &hello(), 5)
        .meta([("note", big.as_str())])
        .build()
        .unwrap_err();
    assert_eq!(err.code, Code::TooLarge);
}

#[test]
fn outside_the_subset_is_bad_manifest() {
    let err = refused(with("x", Some(Value::Float(0.5))));
    assert_eq!(err.code, Code::BadManifest);
    assert!(err.detail.contains("float"), "{}", err.detail);
    // Indefinite lengths only exist in bytes.
    let mut bytes = unhex(A);
    bytes[0] = 0xbf;
    bytes.push(0xff);
    assert!(
        Manifest::decode(&bytes)
            .unwrap_err()
            .detail
            .contains("indefinite")
    );
}

#[test]
fn format_must_be_one() {
    assert!(refused(with("format", None)).detail.contains("no format"));
    assert!(
        refused(with("format", Some(Value::Integer(2.into()))))
            .detail
            .contains("is not 1")
    );
    assert!(
        refused(with("format", Some(t("1"))))
            .detail
            .contains("unsigned")
    );
}

#[test]
fn required_names_are_checked() {
    for key in ["kind", "name", "version"] {
        let err = refused(with(key, None));
        assert_eq!(err.code, Code::BadManifest);
        assert!(err.detail.contains(&format!("no {key}")), "{}", err.detail);
        assert!(
            refused(with(key, Some(Value::Integer(1.into()))))
                .detail
                .contains("not text")
        );
    }
    let err = refused(with("kind", Some(t("App"))));
    assert_eq!(err.code, Code::BadManifest);
    assert!(err.detail.contains("kind"));
    assert_eq!(
        refused(with("name", Some(t("CON")))).code,
        Code::BadManifest
    );
    assert_eq!(
        refused(with("version", Some(t("e\u{301}")))).code,
        Code::BadManifest
    );
}

#[test]
fn files_must_be_an_array() {
    assert!(refused(with("files", None)).detail.contains("no files"));
    assert!(
        refused(with("files", Some(t("x"))))
            .detail
            .contains("no files")
    );
}

#[test]
fn a_manifest_may_list_no_files() {
    // A later list of versions is a manifest that names its members in
    // `deps` and has no files of its own.
    let m = Manifest::from_value(with("files", Some(Value::Array(vec![])))).unwrap();
    assert!(m.files().is_empty());
}

#[test]
fn the_byte_cap_bounds_the_number_of_files() {
    let files = |n: usize| Value::Array((0..n).map(|i| file(&format!("f{i}"))).collect());
    Manifest::from_value(with("files", Some(files(2000)))).unwrap();
    let err = refused(with("files", Some(files(2600))));
    assert_eq!(err.code, Code::TooLarge);
}

#[test]
fn each_file_needs_path_digest_and_size() {
    for key in ["path", "digest", "size"] {
        let Value::Map(mut entries) = file("a") else {
            unreachable!()
        };
        entries.retain(|(k, _)| k.as_text() != Some(key));
        let err = refused(with("files", Some(Value::Array(vec![Value::Map(entries)]))));
        assert!(
            err.detail.contains(&format!("no {key}")),
            "{key}: {}",
            err.detail
        );
    }
    let negative = map(vec![
        ("path", t("a")),
        ("digest", Value::serialized(&hello()).unwrap()),
        ("size", Value::Integer((-1).into())),
    ]);
    assert!(
        refused(with("files", Some(Value::Array(vec![negative]))))
            .detail
            .contains("negative")
    );
}

#[test]
fn file_paths_are_checked() {
    for path in ["/abs", r"a\b", "a/../b", "CON.pak", "a/b."] {
        let err = refused(with("files", Some(Value::Array(vec![file(path)]))));
        assert_eq!(err.code, Code::BadManifest, "{path}");
    }
    let twins = Value::Array(vec![file("Mod.pak"), file("mod.pak")]);
    assert!(refused(with("files", Some(twins))).detail.contains("case"));
    let nested = Value::Array(vec![file("data"), file("data/x")]);
    assert!(
        refused(with("files", Some(nested)))
            .detail
            .contains("under another")
    );
}

#[test]
fn file_digests_are_checked() {
    let digest = |alg: &str, hex: &str, extra: bool| {
        let mut d = vec![("alg", t(alg)), ("hex", t(hex))];
        if extra {
            d.push(("size", Value::Integer(5.into())));
        }
        let f = map(vec![
            ("path", t("a")),
            ("digest", map(d)),
            ("size", Value::Integer(5.into())),
        ]);
        with("files", Some(Value::Array(vec![f])))
    };
    let hex = hello().hex().to_owned();
    Manifest::from_value(digest("sha256", &hex, false)).unwrap();
    assert_eq!(
        refused(digest("blake3", &hex, false)).code,
        Code::UnsupportedAlg
    );
    assert_eq!(
        refused(digest("sha256", &hex[1..], false)).code,
        Code::BadManifest
    );
    assert!(
        refused(digest("sha256", &hex, true))
            .detail
            .contains("\"size\"")
    );
}

#[test]
fn meta_is_text_to_text_with_nfc_keys() {
    let ok = map(vec![("game", t("bg3"))]);
    Manifest::from_value(with("meta", Some(ok))).unwrap();
    assert!(
        refused(with("meta", Some(t("x"))))
            .detail
            .contains("not a map")
    );
    let number = map(vec![("game", Value::Integer(3.into()))]);
    assert!(
        refused(with("meta", Some(number)))
            .detail
            .contains("not text")
    );
    let nfd = map(vec![("e\u{301}", t("x"))]);
    assert!(refused(with("meta", Some(nfd))).detail.contains("NFC"));
}

#[test]
fn target_needs_os_and_arch() {
    let full = map(vec![("os", t("linux")), ("arch", t("arm"))]);
    Manifest::from_value(with("target", Some(full))).unwrap();
    assert!(
        refused(with("target", Some(map(vec![("os", t("linux"))]))))
            .detail
            .contains("no arch")
    );
    assert!(
        refused(with("target", Some(map(vec![("arch", t("arm"))]))))
            .detail
            .contains("no os")
    );
}

#[test]
fn deps_are_checked() {
    let dep =
        |kind: &str, name: &str| map(vec![("kind", t(kind)), ("name", t(name)), ("req", t("*"))]);
    Manifest::from_value(with("deps", Some(Value::Array(vec![dep("mod", "x")])))).unwrap();
    assert!(
        refused(with("deps", Some(t("x"))))
            .detail
            .contains("not an array")
    );
    assert_eq!(
        refused(with("deps", Some(Value::Array(vec![dep("Mod", "x")])))).code,
        Code::BadManifest
    );
    assert_eq!(
        refused(with("deps", Some(Value::Array(vec![dep("mod", "a/b")])))).code,
        Code::BadManifest
    );
    let no_req = map(vec![("kind", t("mod")), ("name", t("x"))]);
    assert!(
        refused(with("deps", Some(Value::Array(vec![no_req]))))
            .detail
            .contains("no req")
    );
}

#[test]
fn only_upload_origins_are_defined() {
    let origin = |ty: &str| with("origin", Some(map(vec![("type", t(ty))])));
    Manifest::from_value(origin("upload")).unwrap();
    for ty in ["source", "upstream", "patch"] {
        assert!(
            refused(origin(ty)).detail.contains("not defined yet"),
            "{ty}"
        );
    }
    assert!(
        refused(with("origin", Some(map(vec![]))))
            .detail
            .contains("no type")
    );
}

#[test]
fn created_is_unsigned_milliseconds() {
    let m = Manifest::from_value(with(
        "created",
        Some(Value::Integer(1_764_054_000_000u64.into())),
    ))
    .unwrap();
    assert_eq!(m.created(), Some(1_764_054_000_000));
    assert!(
        refused(with("created", Some(Value::Integer((-1).into()))))
            .detail
            .contains("negative")
    );
    assert!(
        refused(with("created", Some(t("now"))))
            .detail
            .contains("unsigned")
    );
}

#[test]
fn a_new_created_is_a_new_manifest() {
    let a = builder().file("a", &hello(), 5).created(1).build().unwrap();
    let b = builder().file("a", &hello(), 5).created(2).build().unwrap();
    assert_ne!(a.digest(), b.digest());
}

#[test]
fn the_manifest_must_be_a_map() {
    assert!(refused(Value::Array(vec![])).detail.contains("not a map"));
}
