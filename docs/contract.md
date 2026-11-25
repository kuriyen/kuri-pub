# The depot contract

What a kuri-pub depot and its clients agree on: the values they exchange, the
manifest that describes a version, the methods of the Kuri Link app `pub`, and
the faults. The crate `kuri-pub` implements it; the server is `kuri-pub-depot`.

Both tables (methods, manifest keys) only grow once released. A reader ignores
what it does not know; a depot keeps it.

**Requests are checked, replies are read as written.** The depot enforces the
rules below on what it receives, and a client checks them when it builds a
request. In a reply, kinds, names, versions and channels are plain text and a
digest is read whatever its `alg`, so a client checks a value only when it is
about to use it. That is what makes loosening a rule an addition: a depot that
allows more still answers an older client, which reads the whole page and
skips what it cannot act on. Tightening a rule would break what is published.

## 1. Values shared by both tables

| Name | Encoding | Rule |
|---|---|---|
| `Digest` | map `{alg: text, hex: text}`, exactly these two keys | `alg` is `"sha256"` in the first release. Any other value is refused with `unsupported_alg`, not ignored. The second value is reserved for Fuchsia's Merkle root (§5). `hex` is lowercase, length fixed by `alg` (64). A malformed `hex` is `bad_name` in an argument and `bad_manifest` in a manifest. |
| kind | text | One segment `[a-z0-9][a-z0-9-]{0,63}`, optionally `.` and a second such segment (`app`, `mod.bg3`). Open: the depot never checks it against a list. |
| channel | text | One segment, as the first part of a kind. |
| name | text | 1–128 bytes, **segment rule** below. Unique within a kind, compared bytewise (NFC makes that what a person sees). |
| version | text | 1–64 bytes, segment rule. **Opaque**: the depot never orders versions. "Latest" is a channel, not a comparison. |
| time | uint | **Milliseconds** since the Unix epoch, UTC. |

**Segment rule** (a name, a version, each segment of a path):
- non-empty and in Unicode NFC (not normalized for the caller; refused);
- no control character (`Cc`, which includes NUL);
- none of `/ \ : < > " | ? *`;
- does not end in `.` or a space (so not `.` or `..`);
- not a Windows device name, in any case, compared on the part before the first `.`: `CON PRN AUX NUL COM1–9 LPT1–9 COM¹ COM² COM³ LPT¹ LPT² LPT³ CONIN$ CONOUT$`.

Failures are `bad_name` for an argument and `bad_manifest` inside a manifest.

## 2. Manifest

A CBOR map with text keys. A reader ignores keys it does not know. The depot **keeps** them at every depth, so an older depot does not strip what a newer front end wrote.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `format` | uint | yes | `1`. Raised only if a change cannot be expressed by adding a key; the depot refuses a format it does not know. |
| `kind` | text | yes | as §1 |
| `name` | text | yes | as §1 |
| `version` | text | yes | as §1 |
| `files` | array of `{path: text, digest: Digest, size: uint}` | yes, may be empty | `path`: relative, `/`-separated, each segment by the segment rule, ≤ 1024 bytes. Unique after lowercasing, and no path is a directory prefix of another after lowercasing (`a` with `A/b`). Lowercasing is Unicode's full mapping, an approximation of NTFS's own upcase table that differs on a few characters (`ß`/`ẞ`, final `ς`). Empty is allowed for a manifest that only names others in `deps` (§5). |
| `meta` | map text → text | no | Per-kind facts the depot does not interpret. Keys NFC. Open. |
| `target` | `{os: text, arch: text}` | no | Rust's `std::env::consts::{OS, ARCH}` spellings. Absent means any. |
| `deps` | array of `{kind, name, req: text}` | no | Recorded only; nothing resolves them yet. `req` is opaque. |
| `origin` | map with `type: text` | no | `"upload"` in the first release. `"source"`, `"upstream"`, `"patch"` and their fields are reserved for patches and sources; the depot refuses them until they are defined. |
| `created` | time | no | The publisher's claim. The depot's own time is `published` in the index. |

**Encoding subset.** Text map keys only; no floats, no tags, no indefinite lengths, no duplicate keys; simple values only `false`, `true` and `null`. Anything else is `bad_manifest`.

**Identity of a version.** `(kind, name, version)` names it. Its content is the manifest's digest, taken over the manifest re-encoded deterministically (RFC 8949 §4.2.1: shortest integers and lengths, map keys sorted bytewise by their encoding), unknown keys included. That canonical form is what the depot stores, as a blob like any other. A retry must resend **the same manifest**: a new `created` is a new manifest, and gets `conflict`.

**Limits.** The manifest as received and as encoded is ≤ 256 KiB, so it fits a Kuri Link frame (1 MiB) with the call envelope. It is also what bounds the number of files: an entry takes at least 103 bytes, so a manifest holds at most about 2,500 files, and about 2,000 with typical paths.

## 3. Methods of app `pub`

Every caller reaching the depot has been admitted by the home's gateway. The first release makes no further distinction. Read and write can be granted apart without changing this contract: Kuri Link's `AuthRequest` carries the method. A read-only grant is `kinds`, `list`, `versions`, `manifest`, `has`, `get`.

### `call`

| Method | Args | Returns | Faults |
|---|---|---|---|
| `kinds` | `{}` | `[{kind, names: uint}]`, bytewise order | — |
| `list` | `{kind, after?: name, limit?: uint}` | `{items: [{name, versions: uint, channels: {channel → {version, seq}}}], next?: name}`, bytewise order | `bad_name` |
| `versions` | `{kind, name, after?: version, limit?: uint}` | `{items: [{version, manifest: Digest, published: time}], next?: version}`, publish order | `bad_name`, `not_found` |
| `manifest` | `{kind, name, version}` **or** `{kind, name, channel}` | `{version, digest: Digest, manifest, seq?: uint}`; `seq` present when asked by channel | `bad_name`, `not_found` |
| `has` | `{digests: [Digest]}` (≤ 1024) | `[bool]`, same order | `unsupported_alg`, `too_large` |
| `publish` | `{manifest}` | `{digest: Digest, created: bool}` | `bad_manifest`, `missing_blobs`, `conflict`, `too_large`, `unsupported_alg` |
| `set_channel` | `{kind, name, channel, version, expect?: uint}` | `{previous: version or null, seq: uint}` | `bad_name`, `not_found` (version), `channel_moved` |

- In the Returns column, `kind`, `name`, `version` and `channel` are text read as written, and a `Digest` is read whatever its `alg` (see the top of this document).
- `after` is a cursor: the `next` of the previous page, passed back as given. The depot compares it bytewise and checks no rule on it.
- `limit` defaults to 100 and is capped at 1000. Paging is by the last key seen, so a list does not shift under concurrent publishes.
- `publish` checks that every file's blob is present **and** has the size the manifest claims. The same canonical digest as the stored version succeeds with `created: false`. A different one is `conflict`, whose detail names the stored digest (`conflict: stored sha256:<hex>`). A version is never deleted or replaced.
- `missing_blobs` is a fallback. A client calls `has` first and uploads what is missing. The fault's detail is for people.
- `seq` starts at 1 for each channel and grows by one on every move, a rollback included. A client refuses a reply whose `seq` is below one it has seen for that channel.
- `expect` is the `seq` the caller last saw, `0` for "the channel does not exist yet". When given and different from the channel's current `seq`, the move is refused with `channel_moved`. Rolling back is `set_channel` to an older version.

### `open`

| Method | Args | Stream | Faults at accept |
|---|---|---|---|
| `get` | `{digest, offset?: uint}` | Server → client: the blob's bytes from `offset` to the end, then end-of-stream. Client → server: nothing. | `not_found`, `bad_range` (offset > size), `unsupported_alg` |
| `put` | `{digest, size}` | Client → server: exactly `size` bytes, then end-of-stream. Server → client: one CBOR result, `{stored: bool}` or `{error: {code, detail}}`, then end-of-stream. | `unsupported_alg`, `too_large` |

- `get` resumes by asking again with a later `offset`. The client checks the digest over the whole file it assembled. The server reads in fixed chunks.
- `put` streams into a temporary file in the store's own directory while hashing, with a fixed 64 KiB buffer. On end-of-stream it checks size and digest, `fsync`s the file, renames it into place, and `fsync`s the directory. On a mismatch the temporary file is removed and the result is `digest_mismatch` or `size_mismatch`. A blob already present is answered `{stored: false}` at once and the server stops reading; a client reads the result before treating a write error as the outcome. A dropped `put` leaves no partial blob. Resuming a `put` is not supported yet.
- Size cap per blob: a depot setting, default 64 GiB (`too_large`).

## 4. Faults

Kuri Link gives an application one fault, `App`, with a text message. kuri-pub's message is always `<code>: <detail>`. `code` comes from the list below, is snake_case and stable; `detail` is for people. The contract crate exports the codes as an enum with an `Unknown(String)` arm and a parser.

`bad_name`, `bad_manifest`, `bad_range`, `not_found`, `conflict`, `missing_blobs`, `digest_mismatch`, `size_mismatch`, `channel_moved`, `too_large`, `unsupported_alg`, `storage`.

## 5. Not in this contract

- **Signatures.** When they come, they sign index entries `(kind, name, version) → digest` and channel pointers with their `seq`, as TUF's targets metadata does. A manifest never carries its own signature, since its digest would have to cover itself.
- **A second `alg`.** Reserved for Fuchsia's Merkle root: an SHA-256 tree over 8 KiB chunks. It lets `get` verify each chunk as it arrives, and lets the depot appear as a package repository to a Fuchsia resolver.
- **Lists** (a set of versions to fetch together): later, as a manifest of kind `list` whose `deps` name its members and whose `files` is empty. That needs no new method and no change to the manifest.
- **Delivering to a share, an inbox, patch origins**: not decided.
- **Delete / garbage collection**: nothing is removed yet.

## 6. Store layout (not part of the wire)

```
store/blobs/sha256/ab/abcdef…     content, read-only once renamed
store/tmp/                         put in progress; emptied at start
store/index/log                    append-only: length-prefixed CBOR records with a checksum, fsynced per append
store/index/snapshot               the compacted log; written to a temporary file, synced, renamed
```

On start the depot loads the snapshot, replays the log, and cuts off a torn last record. All of this is pure Rust; there is no C to cross-compile for armv7.
