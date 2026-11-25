"""Checks that every guard of the contract crate is tested.

Removes one guard at a time, runs the crate's tests, and expects some test to
fail. A guard whose removal leaves every test green is untested. Run from the
repository root: `python3 tools/guards.py [NAME...]`. When a guard is added,
add its mutation here.
"""
import subprocess, sys, pathlib
S = pathlib.Path("crates/kuri-pub/src")
M = [
 ("segment: empty", "names.rs", "    if s.is_empty() {\n        return Err(\"is empty\"", "    if false {\n        return Err(\"is empty\"", 0),
 ("segment: NFC", "names.rs", "if !is_nfc(s) {", "if false {", 0),
 ("segment: control", "names.rs", "find(|c| c.is_control())", "find(|_| false)", 0),
 ("segment: forbidden chars", "names.rs", "find(|c| FORBIDDEN.contains(c))", "find(|_| false)", 0),
 ("segment: trailing dot/space", "names.rs", "if s.ends_with(['.', ' ']) {", "if false {", 0),
 ("segment: device names", "names.rs", "if RESERVED.iter().any(", "if false && RESERVED.iter().any(", 0),
 ("segment: device names ignore extension", "names.rs", "s.split('.').next().unwrap_or(s)", "s", 0),
 ("label: non-empty", "names.rs", "    !b.is_empty()\n", "    true\n", 0),
 ("label: length", "names.rs", "&& b.len() <= MAX_LABEL", "", 0),
 ("label: first char", "names.rs", "&& (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())", "", 0),
 ("label: charset", "names.rs", "|| *c == b'-')", "|| *c == b'-' || *c == b'_')", 0),
 ("kind: second label checked", "names.rs", "is_label(head) && is_label(tail)", "is_label(head)", 0),
 ("name: length", "names.rs", "if s.len() > MAX_NAME {", "if false {", 0),
 ("version: length", "names.rs", "if s.len() > MAX_VERSION {", "if false {", 0),
 ("path: length", "names.rs", "if path.len() > MAX_PATH {", "if false {", 0),
 ("path: segments", "names.rs", "        check_segment(segment)\n", "        Ok::<(), String>(())\n", 0),
 ("paths: case folding", "names.rs", "p.to_lowercase()", "p.to_owned()", 0),
 ("paths: duplicates", "names.rs", "if !seen.insert(key.as_str()) {", "if !seen.insert(key.as_str()) && false {", 0),
 ("paths: file under file", "names.rs", "if seen.contains(&key[..i]) {", "if false {", 0),
 ("digest: alg", "digest.rs", "\"sha256\" => Ok(Alg::Sha256),\n            _ => Err(", "_ => Ok(Alg::Sha256),\n            #[allow(unreachable_patterns)] _ => Err(", 0),
 ("digest: hex length", "digest.rs", "if hex.len() != alg.hex_len() {", "if false {", 0),
 ("digest: lowercase hex", "digest.rs", "        if !hex\n", "        if false && !hex\n", 0),
 ("digest: wire keys exact", "digest.rs", "#[serde(deny_unknown_fields)]\n", "", 0),
 ("check: depth", "cbor.rs", "    if depth > MAX_DEPTH {", "    if false {", 0),
 ("check: float", "cbor.rs", "Value::Float(_) => Err(\"a float; use an integer or text\".into()),", "Value::Float(_) => Ok(()),", 0),
 ("check: tag", "cbor.rs", "Value::Tag(tag, _) => Err(format!(\"tag {tag}; tags are not allowed\")),", "Value::Tag(_, v) => check_at(v, depth + 1),", 0),
 ("check: text keys", "cbor.rs", "let Value::Text(k) = k else {\n                    return Err(\"a map key that is not text\".into());\n                };", "let Value::Text(k) = k else {\n                    continue;\n                };", 0),
 ("check: duplicate keys", "cbor.rs", "if !keys.insert(k.as_str()) {", "if !keys.insert(k.clone()) && false {", 0),
 ("decode: trailing bytes", "cbor.rs", "if r.at != bytes.len() {", "if false {", 0),
 ("decode: indefinite", "cbor.rs", "31 => return Err(\"an indefinite length\".into()),", "31 => 0,", 0),
 ("decode: reserved info", "cbor.rs", "_ => return Err(format!(\"reserved additional information {info}\")),", "_ => 0,", 0),
 ("decode: depth", "cbor.rs", "        if depth > MAX_DEPTH {", "        if false {", 0),
 ("decode: text keys", "cbor.rs", "let Value::Text(k) = self.value(depth + 1)? else {\n                        return Err(\"a map key that is not text\".into());\n                    };", "let k = match self.value(depth + 1)? { Value::Text(k) => k, _ => String::new() };", 0),
 ("decode: duplicate keys", "cbor.rs", "if !keys.insert(k.clone()) {", "if !keys.insert(k.clone()) && false {", 0),
 ("decode: tag", "cbor.rs", "6 => return Err(format!(\"tag {n}; tags are not allowed\")),", "6 => self.value(depth + 1)?,", 0),
 ("decode: float", "cbor.rs", "25..=27 => return Err(\"a float; use an integer or text\".into()),", "25..=27 => Value::Null,", 0),
 ("decode: other simple", "cbor.rs", "_ => return Err(format!(\"the simple value {n}\")),", "_ => Value::Null,", 0),
 ("manifest: received size", "manifest.rs", "        if bytes.len() > MAX_MANIFEST {\n            return Err(Fault::new(\n                Code::TooLarge,\n                format!(\"manifest is", "        if false {\n            return Err(Fault::new(\n                Code::TooLarge,\n                format!(\"manifest is", 0),
 ("manifest: encoded size", "manifest.rs", "        if bytes.len() > MAX_MANIFEST {\n            return Err(Fault::new(\n                Code::TooLarge,\n                format!(\n                    \"manifest encodes", "        if false {\n            return Err(Fault::new(\n                Code::TooLarge,\n                format!(\n                    \"manifest encodes", 0),
 ("manifest: subset on from_value", "manifest.rs", "let bytes = cbor::encode(&value).map_err(", "let bytes = cbor::encode(&value).or_else(|_| Ok::<Vec<u8>, String>(Vec::new())).map_err(", 0),
 ("manifest: format", "manifest.rs", "if uint(format, \"format\")? != FORMAT {", "if false {", 0),
 ("manifest: unsigned", "manifest.rs", "u64::try_from(*i).map_err(|_| bad(format!(\"{what} is negative\")))", "Ok(u64::try_from(*i).unwrap_or(0))", 0),
 ("manifest: meta NFC", "manifest.rs", "if !unicode_normalization::is_nfc(k) {", "if false {", 0),
 ("manifest: unsupported alg kept", "manifest.rs", "Code::UnsupportedAlg => fault,", "Code::UnsupportedAlg => bad(fault.detail),", 0),
 ("manifest: origin upload only", "manifest.rs", "other => return Err(bad(format!(\"origin type {other:?} is not defined yet\"))),", "_ => Some(Origin::Upload),", 0),
 ("manifest: paths checked", "manifest.rs", "check_path(path).map_err(bad)?;", "", 0),
 ("manifest: paths together", "manifest.rs", "check_paths_together(files.iter().map(|f| f.path.as_str())).map_err(bad)?;", "", 0),
 ("manifest: digest keys exact", "manifest.rs", "if let Some(extra) = d.keys().find(|k| !matches!(**k, \"alg\" | \"hex\")) {", "if let Some(extra) = d.keys().find(|_| false) {", 0),
 ("segment: console devices", "names.rs", "\"CONIN$\", \"CONOUT$\",", "\"CON\", \"CON\",", 0),
 ("reply: kinds as text", "methods.rs", "/// The kind, as the depot reports it.\n    pub kind: String,", "/// The kind, as the depot reports it.\n    pub kind: Kind,", 0),
 ("reply: list name as text", "methods.rs", "/// The name, as the depot reports it.\n    pub name: String,", "/// The name, as the depot reports it.\n    pub name: Name,", 0),
 ("reply: channel names as text", "methods.rs", "pub channels: BTreeMap<String, ChannelPointer>,", "pub channels: BTreeMap<Channel, ChannelPointer>,", 0),
 ("reply: channel version as text", "methods.rs", "/// The version it points at, as the depot reports it.\n    pub version: String,", "/// The version it points at, as the depot reports it.\n    pub version: Version,", 0),
 ("reply: list cursor as text", "methods.rs", "pub items: Vec<ListItem>,\n    /// Pass as `after` for the next page; absent on the last.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub next: Option<String>,", "pub items: Vec<ListItem>,\n    /// Pass as `after` for the next page; absent on the last.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub next: Option<Name>,", 0),
 ("reply: versions cursor as text", "methods.rs", "pub items: Vec<VersionItem>,\n    /// Pass as `after` for the next page; absent on the last.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub next: Option<String>,", "pub items: Vec<VersionItem>,\n    /// Pass as `after` for the next page; absent on the last.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub next: Option<Version>,", 0),
 ("reply: version item as text", "methods.rs", "pub struct VersionItem {\n    /// The version, as the depot reports it.\n    pub version: String,", "pub struct VersionItem {\n    /// The version, as the depot reports it.\n    pub version: Version,", 0),
 ("reply: version item digest reported", "methods.rs", "pub manifest: ReportedDigest,", "pub manifest: Digest,", 0),
 ("reply: manifest version as text", "methods.rs", "pub struct ManifestReply {\n    /// The version, as the depot reports it.\n    pub version: String,", "pub struct ManifestReply {\n    /// The version, as the depot reports it.\n    pub version: Version,", 0),
 ("reply: manifest digest reported", "methods.rs", "pub struct ManifestReply {\n    /// The version, as the depot reports it.\n    pub version: String,\n    /// The manifest's digest.\n    pub digest: ReportedDigest,", "pub struct ManifestReply {\n    /// The version, as the depot reports it.\n    pub version: String,\n    /// The manifest's digest.\n    pub digest: Digest,", 0),
 ("reply: publish digest reported", "methods.rs", "pub struct PublishReply {\n    /// The manifest's digest.\n    pub digest: ReportedDigest,", "pub struct PublishReply {\n    /// The manifest's digest.\n    pub digest: Digest,", 0),
 ("reply: previous as text", "methods.rs", "pub previous: Option<String>,", "pub previous: Option<Version>,", 0),
 ("request: list cursor as text", "methods.rs", "/// Start after this name; the previous page's `next`, as given.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub after: Option<String>,", "/// Start after this name; the previous page's `next`, as given.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub after: Option<Name>,", 0),
 ("request: versions cursor as text", "methods.rs", "/// Start after this version; the previous page's `next`, as given.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub after: Option<String>,", "/// Start after this version; the previous page's `next`, as given.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub after: Option<Version>,", 0),
 ("digest: reported checked when used", "digest.rs", "        Digest::new(&self.alg, self.hex.clone())\n", "        Ok(Digest { alg: Alg::Sha256, hex: self.hex.clone() })\n", 0),
 ("methods: page cap", "methods.rs", ".clamp(1, MAX_LIMIT)", ".max(1)", 0),
 ("methods: page floor", "methods.rs", ".clamp(1, MAX_LIMIT)", ".min(MAX_LIMIT)", 0),
 ("methods: has cap", "methods.rs", "if self.digests.len() > MAX_HAS {", "if false {", 0),
 ("methods: version xor channel", "methods.rs", "(None, Some(c)) => Ok(At::Channel(c)),", "(_, Some(c)) => Ok(At::Channel(c)),", 0),
 ("fault: code shape", "fault.rs", "Some((code, detail)) if is_code(code) =>", "Some((code, detail)) =>", 0),
]
only = sys.argv[1:]
bad = []
for name, f, old, new, _ in M:
    if only and name not in only: continue
    p = S / f; src = p.read_text()
    n = src.count(old)
    if n < 1: bad.append(f"{name}: pattern not found"); print("NOPATTERN", name); continue
    p.write_text(src.replace(old, new, 1))
    try:
        r = subprocess.run(["cargo", "test", "-q", "-p", "kuri-pub", "--lib"], capture_output=True, text=True)
        out = r.stdout + r.stderr
        if r.returncode == 0: bad.append(f"{name}: SURVIVED"); print("SURVIVED", name)
        elif "error[" in out and "test result" not in out: bad.append(f"{name}: did not compile"); print("NOCOMPILE", name, out[out.find('error['):][:300])
        else: print("killed  ", name)
    finally:
        p.write_text(src)
print("\n".join(bad) or "all killed", f"({len(M)} mutations)")
