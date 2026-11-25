# kuri-pub — "pub" is short for patch hub

The home's own version repository. It keeps every version of what a home
installs — apps and game mods first, dependencies and libraries later — along
with the patches made to them, and serves them to the home's devices over
[Kuri Link](https://github.com/kuriyen/kuri-link).

kuri-pub is part of [Kuriyen](https://github.com/kuriyen).

> **Status:** the contract is written ([docs/contract.md](docs/contract.md)) and
> implemented by the crate `kuri-pub`. The depot that serves it is the crate
> `kuri-pub-depot`, a library and a binary. No front end yet.

## Running a depot

```text
kuri-pub-depot --store DIR [--max-blob BYTES]
               [--port PORT | --bind ADDR] [--port-mapping]
               [--peers FILE] [--key FILE] [--relay URL]... [--local-discovery]
kuri-pub-depot --store DIR --gateway FILE [--gateway-ticket TICKET] [--key FILE]
               [--local-discovery]
```

`DIR` holds the blobs and the index, and is created if it is new. Listening,
the depot prints a one-line pairing ticket for one device; behind a home's
Kuri Link gateway, the gateway pairs the devices instead. Keep `--key` (and
`--peers` when listening) so the depot is the same node after a restart.
`--local-discovery` announces the depot by mDNS on the local network; it is
off unless given, since the announcement shows everyone there the depot's key
and addresses. One depot at a time may open a store: a second one is refused.

Its memory does not grow with what it stores or serves: uploads stream through
a fixed buffer into a temporary file in the store, downloads are read a fixed
chunk at a time, and the index in memory holds names and digests only. It runs
on 32-bit ARM.

Not yet:
- **Reads wait for a publish's sync.** The index takes one lock, and a publish
  or channel move holds it while the log is synced, so every read of the index
  waits for that sync.
- **No idle timeout and no quota on uploads.** A `put` that stops sending
  holds its temporary file until its connection closes, and nothing caps the
  total a store may hold; only one blob's size is capped (`--max-blob`).

Before contributing, read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this work,
as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
