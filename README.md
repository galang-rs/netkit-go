# NetKit-Go 🚀

A powerful networking toolkit for traffic interception, MITM proxying, and transparent capture — built for speed and flexibility with a full-featured JavaScript scripting engine.

## Features

- **TLS MITM**: Intercept and decrypt HTTPS traffic with automatic certificate generation.
- **SOCKS5 / HTTP Proxy**: Built-in proxy servers with optional authentication.
- **Transparent Capture**: DNS Hijacking + Hosts modification for apps without proxy support.
- **JS Scripting Engine**: Full-featured JavaScript runtime (Goja) with 25+ built-in modules.
- **CGNAT Bypass**: Automatic NAT detection and bypass (UPnP, STUN, hole-punching, MikroTik).
- **NK-Tunnel**: Self-hosted TCP/UDP tunneling for CGNAT environments.
- **Ad-Blocking**: Engine-level ad detection with HTML sanitization and request dropping.
- **Node.js Bridge**: Run NPM packages from JS scripts via `runNodeJS()`.
- **IDS Engine**: Signature-based intrusion detection with regex/pattern matching.
- **Raw Networking**: TCP/UDP sockets, raw IP packets, TLS manipulation.
- **PCAP Logging**: Export captured traffic to standard PCAP files for Wireshark.
- **Application Tracking**: Launch and track specific applications for targeted interception.

## Prerequisites

- **Go**: 1.25+ recommended.
- **Npcap**: Required for raw socket capture (Sniffer mode). Install in "WinPcap API-compatible Mode".
- **Node.js**: Optional, required only for `runNodeJS()` bridge functionality.

## Getting Started

### 1. Generate Root CA
```powershell
go run main.go --gen-ca
```

### 2. Trust the Certificate
Run as **Administrator**:
```powershell
certutil -addstore -f "Root" "ca.crt"
```

### 3. Quick Start — JS Scripting 📜

Save as `scripts/log.js`:

```javascript
function init() {
    console.log("🚀 NetKit-Go Started");

    // Create a SOCKS5 Proxy with Auth
    Proxy.Create({
        addr: ":11080",
        type: "socks5",
        auth: { user: "admin", pass: "1234" }
    });

    // Start a monitoring API server
    const app = http.createServer();
    app.get("/api/metrics", (req, res) => {
        res.json(Metrics.Snapshot());
    });
    app.listen(8081);
}

function onConnect(info) {
    console.log(`🔌 ${info.type} from ${info.ip} through ${info.through}`);

    if (info.dest.includes("google.com")) {
        return connect.proxy("http://127.0.0.1:8080");
    }
}

function onResponse(ctx) {
    const body = ctx.Flow.Body().WaitFullContent();
    if (body) {
        console.log(`📦 [${ctx.FullURL}]: ${body.substring(0, 100)}...`);
    }
}

function onAds(ctx) {
    if (ctx.Ad && ctx.Ad.is_ad) {
        if (ctx.Flow.ContentType().includes("html")) {
            ctx.Flow.Sanitize();
        } else {
            ctx.Drop();
        }
    }
}
```

Run with your script:
```powershell
go run main.go --script scripts/log.js --mitm-all
```

---

## JavaScript API

For the full API reference, see **[JS_API.md](JS_API.md)**.

<details>
<summary><b>Lifecycle Hooks</b> (init, onPacket, onAds...)</summary>

| Hook | Description |
|------|-------------|
| `init()` | Runs once when script is loaded |
| `onConnect(info)` | Connection phase hook. Return `connect.*` for tunneling. |
| `onPacket(ctx)` | Called for every packet |
| `onRequest(ctx)` / `onResponse(ctx)` | HTTP-specific hooks (override `onPacket` for HTTP) |
| `onAds(ctx)` | Ad-blocking hook. Use `ctx.Flow.Sanitize()` or `ctx.Drop()`. |
| `onError(err)` | Global error handler |
| `closing()` | Called on shutdown |

</details>

<details>
<summary><b>Context Object</b> (<code>ctx</code>)</summary>

**Actions**: `ctx.Drop()`, `ctx.Modify(payload)`, `ctx.Respond(payload)`, `ctx.Send(payload, opts)`, `ctx.Bypass()`, `ctx.SetPriority(val)`, `ctx.Reference([val])`.

**Properties**: `ctx.Packet`, `ctx.FullURL`, `ctx.Hostname`, `ctx.Session`, `ctx.Conn`, `ctx.Connect`, `ctx.Ad`.

</details>

<details>
<summary><b>Core Modules</b> (25+ built-in)</summary>

| Module | Description |
|--------|-------------|
| `Flow` | HTTP inspection: headers, body, sanitize, inject JS |
| `Proxy` | Dynamic MITM listeners, proxy rotation & dialing |
| `http` | Express-like HTTP server (routes, middleware) |
| `FS` | File I/O, shared cache, packet history |
| `DNS` | Sync/Async DNS lookups |
| `Net` | TCP/UDP sockets with full connection API |
| `TLS` | TLS parsing, SNI extraction/rewriting, fingerprinting |
| `Crypto` | SHA/MD5/HMAC hashing, AES-GCM, Base64, Hex, XOR |
| `CGNAT` | NAT detection, bypass, MikroTik, UPnP, STUN |
| `Mirror` | Traffic recording, replay, and passive cloning (`Tee`) |
| `Script` | Rule management (enable/disable/priority/tags) |
| `Runtime` | `spawn()` and `spawnWithTimeout()` for background goroutines |
| `Tunnel` | NK-Tunnel client & server |
| `Stack` | Raw packet crafting (IPv4/TCP headers, flags) |
| `MIME` | Content-type detection (magic bytes + heuristics) |
| `IDS` | Signature-based intrusion detection |
| `Metrics` | Telemetry counters (PPS, BPS, custom counters) |
| `Traffic` | Rate limiting, throttling, flood detection |
| `Security` | Permission scopes & resource limits |
| `Sync` | Mutex, RWMutex, Atomic, Channel, WorkerPool, EventBus, Map |
| `Mem` | Memory reduction, GC control, runtime stats |
| `Sim` | Network simulation (delay, loss, jitter, corruption) |
| `Account` | TLS fingerprint & cookie persistence |
| `CLI` | Execute system commands |
| `connect` | Tunneling config (`proxy()`, `wg()`, `ssh()`, `cgnat()`, chaining) |
| `fetch` / `FetchAsync` | HTTP requests with TLS fingerprinting |

</details>

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `--script` | Path to JS script (default: `scripts/log.js`) |
| `--mitm-all` | Force MITM interception for ALL domains |
| `--tls` | TLS MITM listen address (e.g. `:8443`) |
| `--tls-target` | TLS MITM target address |
| `--tcp` | TCP MITM listen address |
| `--tcp-target` | TCP MITM target address |
| `--udp` | UDP MITM listen address |
| `--udp-target` | UDP MITM target address |
| `--h3` | HTTP/3 listener address (e.g. `:443`) |
| `--transparent` | Enable transparent HTTPS redirection |
| `--iface` | Local IP address to bind for transparent capture |
| `--domains` | Comma-separated list of domains to redirect |
| `--pcap` | Path to PCAP output file |
| `--app` | Path to application to launch and track |
| `--filter` | Packet filter expression |
| `--mirror` | Mirror traffic to this UDP address |
| `--verbose` | Enable verbose engine logging |
| `--sniff-all` | Bypass PID-specific filtering |
| `--windivert` | Enable WinDivert transparent interception |
| `--dns-spoof` | Enable DNS spoofing |
| `--discovery` | Enable mDNS, SSDP, and NBNS discovery |
| `--happy-eyeballs` | Enable Happy Eyeballs (multi-IP fallback) |
| `--raw` | Enable raw byte capture |
| `--link-domains` | Map IPs to domains in logs |
| `--force-h11` | Force HTTP/1.1 (disable H2/H3) |
| `--adblock` | Enable AdBlock engine |
| `--cgnat` | Enable CGNAT detection and bypass |
| `--debug` | Enable debug/packet inspector mode |
| `--list-ifaces` | List all network interfaces and exit |

### MikroTik Helper Flags

| Flag | Description |
|------|-------------|
| `--mikrotik-host` | MikroTik API host |
| `--mikrotik-user` | MikroTik API username |
| `--mikrotik-pass` | MikroTik API password |

### NK-Tunnel Flags

| Flag | Description |
|------|-------------|
| `--tunnel-server` | Run NK-Tunnel server on this address (e.g. `:9090`) |
| `--tunnel-server-range` | Port range for tunnel server (default: `8000-8010`) |
| `--tunnel-user` | Username for NK-Tunnel (default: `admin`) |
| `--tunnel-pass` | Password for NK-Tunnel (default: `secret`) |
| `--tunnel` | Connect to NK-Tunnel server (`ip:port:user:pass:remote_port:type`) |
