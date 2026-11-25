"""Writes the manifest test vectors with an encoder independent of the crate.

Canonical CBOR as RFC 8949 4.2.1 defines it, and a loose encoding of the same
values. Prints each vector's name, length, hex and SHA-256; the .hex and
.sha256 files beside this script were written from its output.
"""
import hashlib, struct
def head(major, n):
    m = major << 5
    if n < 24: return bytes([m | n])
    if n < 256: return bytes([m | 24, n])
    if n < 65536: return bytes([m | 25]) + struct.pack(">H", n)
    if n < 2**32: return bytes([m | 26]) + struct.pack(">I", n)
    return bytes([m | 27]) + struct.pack(">Q", n)
def enc(v):
    if v is None: return b"\xf6"
    if v is True: return b"\xf5"
    if v is False: return b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted((enc(k), enc(x)) for k, x in v.items())
        return head(5, len(items)) + b"".join(k + x for k, x in items)
def sha(b): return hashlib.sha256(b).hexdigest()
hello = {"alg": "sha256", "hex": sha(b"hello")}
a = {"format": 1, "kind": "app", "name": "hello", "version": "1.0",
     "files": [{"path": "hello.exe", "digest": hello, "size": 5}]}
b = {"format": 1, "kind": "mod.bg3", "name": "Better Camp", "version": "2.1-été",
     "files": [{"path": "Mods/BetterCamp.pak", "digest": hello, "size": 5, "x-mode": 420},
               {"path": "README.txt", "digest": {"alg": "sha256", "hex": sha(b"")}, "size": 0}],
     "meta": {"game": "bg3", "title": "Better Camp"},
     "target": {"os": "windows", "arch": "x86_64"},
     "deps": [{"kind": "mod.bg3", "name": "Script Extender", "req": ">=1"}],
     "origin": {"type": "upload"}, "created": 1764054000000,
     "x-future": {"nested": [1, -2, True, None, b"\x00\x01"], "n": 70000}}
for name, v in [("A", a), ("B", b)]:
    e = enc(v); print(name, len(e), e.hex(), sha(e))
def loose(v):
    # Valid but not canonical: every integer and length in eight bytes, keys reversed.
    def h(major, n): return bytes([(major << 5) | 27]) + struct.pack(">Q", n)
    if isinstance(v, bool) or v is None: return enc(v)
    if isinstance(v, int): return h(0, v) if v >= 0 else h(1, -1 - v)
    if isinstance(v, bytes): return h(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return h(3, len(b)) + b
    if isinstance(v, list): return h(4, len(v)) + b"".join(loose(x) for x in v)
    if isinstance(v, dict):
        return h(5, len(v)) + b"".join(loose(k) + loose(x) for k, x in reversed(list(v.items())))
l = loose(b); print("Bloose", len(l), l.hex())
