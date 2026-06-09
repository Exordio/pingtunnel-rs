# Pingtunnel-rs

[Русский](README.ru.md) | **English**

> An **async (tokio)** implementation: low memory, event-driven, syscall batching,
> configurable frame size (`--jumbo`). Supports TCP, UDP, SOCKS5 (CONNECT and
> UDP ASSOCIATE).

This is a **Rust** rewrite of the original Go project
[esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel). The on-the-wire
protocol is byte-level compatible with the original (protobuf messages and the
frame format are preserved), so the Rust and Go versions can most likely
interoperate.
**(But it is not guaranteed, since changes were made to adapt the code to Rust's
realities.)**

#### **In essence it is the same protocol and the same "TCP/UDP-over-ICMP" model, but rewritten in async Rust with a focus on: syscall batching (less sys-CPU), no GC (flat memory profile), a mutex-free TCP connection path. The cost — auxiliary Go features were dropped (GeoIP, pprof, pool parameters). The bottleneck is the same for both versions — pps (packets per second), not bandwidth, so the main throughput lever is `--jumbo` (larger frame -> fewer packets -> lower CPU).**

> ⚠️ **For research and education only. Do not use for unlawful purposes.**

```
                 ICMP (echo request/reply)
   ┌────────┐   with encapsulated TCP/UDP      ┌────────┐        ┌───────────────┐
   │ client │ ───────────────────────────────▶│ server │ ─────▶│ target address│
   │ (-l)   │ ◀────────────────────────────── │        │◀───── │  (-t / SOCKS) │
   └────────┘                                  └────────┘        └───────────────┘
 local TCP/UDP/SOCKS5                       public IP            real service
```

# Differences?

## 1. Language and runtime

| Characteristic | Go original | This port (Rust) |
|----------------|-------------|------------------|
| Concurrency | goroutines + GC + Go scheduler | async tasks on tokio, no GC |
| Memory | GC, sawtooth profile ~20-1000Mb+, pauses | deterministic, ~20–150 MB, no pauses |
| Per-connection overhead | goroutine (stack ~KB) + channels | tokio task (cheaper than a goroutine) |


## 2. I/O architecture (the main performance difference)
- Syscall batching. This is the key part. The Go version does "one syscall per packet" (ReadFrom/WriteTo). Here — recvmmsg/sendmmsg: dozens of ICMP packets per single kernel call (icmp.rs). This is exactly what removed the bulk of sys-CPU on the server (per the file comment — ~72%).
- Task model. A single read task receives batches and demultiplexes by conn-id, a single write task collects outgoing data and sends it in a batch; each TCP connection is a separate task with its own FrameMgr (sole owner, no Mutex around the frame state).
- Tick/time model. Go uses a cached "now" (updated by a separate goroutine) and a coarse tick. In this port the connection loop was brought to an adaptive tick (10 ms while active / 500 ms when idle) and time caching in update() — previously it was a 1 ms busy-poll.

## 3. Functional differences (features)
- ❌ SOCKS5 GeoIP filter (--s5filter/--s5ftfile) is not implemented — it needs a MaxMind database + an mmdb reader. The flags are accepted for compatibility but do not filter.
- ❌ --profile (pprof) — this is a Go tool, there is no equivalent in Rust.
- ❌ --maxprt/--maxprb (server processing pool parameters) are not needed — dispatching is direct, with no worker pool.
- ✅ TCP forwarding, SOCKS5 CONNECT, plain UDP, SOCKS5 UDP ASSOCIATE, forwarding via a socks5/http proxy, encryption (AES-128/256-GCM, ChaCha20-Poly1305).

## 4. Protocol and compatibility
- The wire format is preserved — the same protobuf MyMsg/Frame/FrameData and the same frame logic, so the Rust and Go sides can in principle talk to each other (but it is not guaranteed).
- The connection ID is 32 random hex characters (in Go — MD5). It does not affect the protocol, it is just a string key.

## Table of contents

- [How it works](#how-it-works)
- [Building](#building)
- [Permissions (important)](#permissions-important)
- [Usage](#usage)
  - [Server](#server)
  - [Client: SOCKS5](#client-socks5)
  - [Client: TCP forwarding](#client-tcp-forwarding)
  - [Client: UDP forwarding](#client-udp-forwarding)
- [Encryption](#encryption)
- [Forwarding via a proxy](#forwarding-via-a-proxy)
- [All command-line options](#all-command-line-options)
- [Implementation architecture](#implementation-architecture)
- [Tests](#tests)
- [License](#license)

## How it works

Every ICMP Echo packet carries in its payload a serialized protobuf message
`MyMsg` (connection identifier, type, target address, data, key, etc.),
optionally encrypted. The client sends an echo request (type 8), the server
replies with an echo reply (type 0).

Since ICMP is an unreliable channel with no delivery or ordering guarantees, for
**TCP** a custom reliable transport `FrameMgr` is implemented on top of it:

- a sliding window and frame numbering;
- retransmission on timeout and on receiver request (REQ);
- cumulative acknowledgements (ACK);
- ping/pong for RTT estimation and heartbeat for liveness control;
- optional frame compression (zlib).

For **UDP** the reliable layer is off by default — datagrams are passed as-is
(unreliably, just like UDP itself). Pass `--udp_rel 1` (client side) to route
datagrams through the **same** `FrameMgr` as TCP: retransmission and ordering are
applied, while datagram boundaries are preserved via a length prefix. Useful when
the ICMP path loses a lot of packets. Works for both plain UDP forwarding (`-t`)
and **SOCKS5 UDP ASSOCIATE** (`--sock5 1`). Only the client needs the flag — the
server detects a reliable-UDP connection from the connect packet.

## Building

Requires Rust (edition 2024, minimum 1.85) and `protoc` (the Protocol Buffers compiler),
which is invoked at build time to generate Rust code from `.proto`.

```bash
# Installing protoc (examples)
#   Arch:   sudo pacman -S protobuf
#   Debian: sudo apt install protobuf-compiler

cargo build --release
# binary: target/release/pingtunnel
```

## Permissions (important)

To receive/send ICMP the server opens a **RAW socket**, which requires `root`
privileges or the `CAP_NET_RAW` capability:

```bash
# option 1 — run as root
sudo ./target/release/pingtunnel --type server --key 123456

# option 2 — grant the capability to the binary (then no sudo needed)
sudo setcap cap_net_raw+ep ./target/release/pingtunnel
./target/release/pingtunnel --type server --key 123456
```

The **client** can additionally work without privileges: if a RAW socket is
unavailable, it automatically falls back to an unprivileged ICMP datagram socket
(if `net.ipv4.ping_group_range` allows it — on most distributions it is allowed
by default). This is the equivalent of the original's android mode. The datagram
mode does not work for the server — it needs RAW.

(Optional) disable the kernel's own ping replies so they don't interfere:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/icmp_echo_ignore_all
```

## Usage

### Server

```bash
sudo ./pingtunnel --type server --key 123456
```

### Client: SOCKS5

Brings up a local SOCKS5 proxy whose entire traffic goes through the ICMP tunnel
to the server (TCP is enabled implicitly):

```bash
./pingtunnel --type client -l :1080 -s SERVER --sock5 1 --key 123456
```

With authentication:

```bash
./pingtunnel --type client -l :1080 -s SERVER --sock5 1 \
             --s5user user --s5pass pass --key 123456
```

### Client: TCP forwarding

All traffic to local port `4455` is forwarded to `SERVER:4455`:

```bash
./pingtunnel --type client -l :4455 -s SERVER -t SERVER:4455 --tcp 1 --key 123456
```

### Client: UDP forwarding

```bash
./pingtunnel --type client -l :4455 -s SERVER -t SERVER:4455 --key 123456
```

> Here `SERVER` is the public IP or domain of the machine running the server,
> and `-t` is the destination address the server will forward traffic to.

Reliable UDP (retransmission + ordering over a lossy ICMP path):

```bash
./pingtunnel --type client -l :4455 -s SERVER -t SERVER:4455 --udp_rel 1 --key 123456
```

## Encryption

The ICMP payload can be encrypted with an AEAD cipher. Supported: `aes128`,
`aes256`, `chacha20`. The key is given as base64 of the required length **or** as
a passphrase (in which case the key is derived via PBKDF2-HMAC-SHA256). The mode
and key must match on the client and the server:

```bash
# server
sudo ./pingtunnel --type server --key 123456 \
     --encrypt chacha20 --encrypt-key "my-secret-phrase"

# client
./pingtunnel --type client -l :1080 -s SERVER --sock5 1 --key 123456 \
     --encrypt chacha20 --encrypt-key "my-secret-phrase"
```

## Forwarding via a proxy

The server can forward outgoing connections not directly, but through an
external proxy (`socks5` or `http` CONNECT):

```bash
sudo ./pingtunnel --type server --key 123456 --forward socks5://localhost:2080
sudo ./pingtunnel --type server --key 123456 --forward http://localhost:8080
```

UDP forwarding via a proxy is supported only for `socks5` (UDP ASSOCIATE).

## All command-line options

| Option          | Purpose                                                            | Default                  |
|-----------------|-------------------------------------------------------------------|--------------------------|
| `--type`        | `client` or `server`                                              | —                        |
| `-l`            | local listen address (client)                                     | —                        |
| `-s`            | server address (client)                                           | —                        |
| `-t`            | target address the server forwards traffic to                     | —                        |
| `--icmp_l`      | ICMP listen address                                               | `0.0.0.0`                |
| `--timeout`     | connection timeout, sec                                           | `60`                     |
| `--key`         | numeric key/password (0..2147483647)                              | `0`                      |
| `--encrypt`     | encryption mode: `aes128`/`aes256`/`chacha20`                     | (off)                    |
| `--encrypt-key` | encryption key (base64 or passphrase)                             | —                        |
| `--tcp`         | enable TCP mode (`1`)                                             | `0`                      |
| `--udp_rel`     | reliable UDP via FrameMgr (`1`; UDP forward & SOCKS5 UDP)         | `0`                      |
| `--tcp_bs`      | TCP buffer size (per connection, each direction)                  | `262144`                 |
| `--tcp_mw`      | maximum window (frames in flight)                                 | `2048`                   |
| `--tcp_rst`     | TCP retransmission time, ms                                       | `400`                    |
| `--tcp_gz`      | TCP data compression threshold (0 — off)                          | `0`                      |
| `--jumbo`       | frame size, B (0 = 888; larger = fewer packets/CPU, e.g. 8000)    | `0`                      |
| `--sock5`       | enable SOCKS5 (implicitly enables TCP)                            | `0`                      |
| `--s5user`      | SOCKS5 username                                                   | (no authentication)      |
| `--s5pass`      | SOCKS5 password                                                   | (no authentication)      |
| `--maxconn`     | maximum connections (0 — unlimited)                              | `0`                      |
| `--conntt`      | server-to-target connect timeout, ms                             | `1000`                   |
| `--forward`     | forwarding via a proxy (`socks5://…` / `http://…`)                | (off)                    |
| `--loglevel`    | log level (`debug`/`info`/`warn`/`error`)                        | `info`                   |
| `--noprint`     | do not print output (`1`)                                        | `0`                      |
| `--s5filter`    | SOCKS5 GeoIP filter — **not supported** (see differences)         | (off)                    |
| `--s5ftfile`    | GeoIP data file — not used                                       | —                        |

## Performance and tuning

The bottleneck of an ICMP tunnel is **not bandwidth, but packets-per-second
(pps)**: every frame travels as a separate ICMP packet, and the ceiling is hit
by how many packets per second the kernel/CPU can process. In practice a single
TCP stream reliably delivers **~50 Mbit/s (~6 MB/s)** even with the default
888 B frame (measured over WAN ~44 ms RTT to a 1-vCPU server) — and noticeably
more with lower RTT, free CPU, raised buffers, `--jumbo`, or multiple streams.

To squeeze out the maximum, on **both the server and the client** (Linux) it
helps to raise the buffers and remove the built-in ICMP limits. Create
`/etc/sysctl.d/99-pingtunnel.conf`:

```ini
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
# incoming packet queue — so the OS does not drop ICMP under a burst
net.core.netdev_max_backlog = 10000
# remove the ICMP rate limit
net.ipv4.icmp_ratelimit = 0
net.ipv4.icmp_ratemask = 0
```

Apply: `sudo sysctl -p /etc/sysctl.d/99-pingtunnel.conf`.

> Without raising `rmem_max/wmem_max`, the kernel by default caps the socket
> buffer at ~200 KB, which makes it hard to hold the window at a noticeable RTT.

**The main throughput "hack" is a larger frame** (`--jumbo N`): fewer packets per
byte → fewer pps → lower CPU and a higher ceiling. By default the frame is 888 B
(masquerading as a regular ping). Single-stream guidelines (depend on
RTT/CPU/link — **it may actually be higher**):

| `--jumbo` | single stream | note |
|-----------|--------------|------|
| 0 (888 B) | **~50 Mbit/s (~6 MB/s)** | default, masquerades as a ping; measured over WAN ~44 ms RTT |
| 1400      | higher | exactly at MTU, no fragmentation |
| 8000      | even higher | best single-stream; >MTU → IP fragmentation. (losses possible) |


### speedtest.net -jumbo 1400 server 1vCpu 2.3hz
<img width="505" height="205" alt="image" src="https://github.com/user-attachments/assets/ec39b50a-b938-430a-8049-d12bffed81be" />


### yandex speedtest -jumbo 1400 server 1vCpu 2.3hz
<img width="1159" height="562" alt="image" src="https://github.com/user-attachments/assets/83213fa5-b431-4b36-a025-720c401f8a80" />


It is set **independently** on the client and the server (each side slices its
own send stream). The cost of a large frame: the ping masquerade is lost, and
above MTU there is IP fragmentation (losing one fragment loses the whole frame →
under high concurrency retransmits grow). The optimum is usually 1400 (no
fragmentation) or 8000 (for single streams).

## Implementation architecture

| File                 | Purpose                                                              |
|----------------------|---------------------------------------------------------------------|
| `src/main.rs`        | argument parsing (clap), launching the client or the server         |
| `src/proto.rs`       | generated protobuf types (`MyMsg`, `Frame`, `FrameData`) and constants |
| `src/icmp.rs`        | ICMP raw/datagram socket, building/parsing echo, packing `MyMsg`, payload encryption |
| `src/framemgr.rs`    | reliable transport over ICMP (sliding window, ACK/REQ, ping/pong, heartbeat, compression) |
| `src/ring.rs`        | ring buffers: byte (`RBuffer`) and by frame id (`ROBuffer`)         |
| `src/crypto.rs`      | AES-128/256-GCM, ChaCha20-Poly1305, key derivation (base64/PBKDF2)  |
| `src/icmp.rs`        | async ICMP socket (`AsyncFd`), `recvmmsg`/`sendmmsg` batching, echo assembly, `MyMsg` |
| `src/socks5.rs`      | SOCKS5: async handshake, request parsing, address encoding, UDP datagrams |
| `src/forward.rs`     | async forwarding via a socks5/http proxy                            |
| `src/client.rs`      | client: accepting local TCP/UDP/SOCKS5, tunneling into ICMP         |
| `src/server.rs`      | server: receiving ICMP, connecting to targets (TCP/UDP, directly or via a proxy) |
| `src/util.rs`        | time, connection id generation, address resolution, counters        |

**The model is async on tokio** (worker pool = number of cores). Each connection
is a task (not an OS thread), driven by events (incoming frame / local data /
timer), with no busy-poll. A single read task receives ICMP in batches
(`recvmmsg`) and demultiplexes by conn-id; a single write task collects outgoing
data and sends it in a batch (`sendmmsg`). For **TCP** each connection holds a
`FrameMgr` (reliable delivery, sole owner without a `Mutex`); for **UDP** —
direct datagram forwarding without a reliable layer (as in the original), or
through `FrameMgr` with `--udp_rel 1` (plain UDP and SOCKS5 UDP ASSOCIATE). Memory
~20–150 MB (depends on the number of connections).

Supported: **TCP forwarding**, **SOCKS5 CONNECT** (TCP), **plain UDP forwarding**
(`-l :port -t host:port` without `--tcp`/`--sock5`) and **SOCKS5 UDP ASSOCIATE**.

## Tests

```bash
cargo test
```

Coverage (21 tests, no privileges required):

- **`framemgr`** — loopback exchange between two `FrameMgr` instances: handshake,
  a multi-frame stream in both directions, **recovery after losing ~1/3 of the
  frames**, compression;
- **`icmp`** — checksum, echo header layout, `MyMsg` round-trip, and also a
  **real round-trip against the kernel's ICMP responder** over loopback;
- **`crypto`** — round-trip for all three modes, failure on a wrong key;
- **`ring`** — ring buffers (wrap-around, overflow, id window);
- **`socks5`** — address and UDP datagram encoding/parsing.

A full end-to-end tunnel test requires RAW-socket privileges for the server:

```bash
sudo ./scripts/e2e_test.sh        # or, after setcap — without sudo
```

## License

MIT — same as the original project.
