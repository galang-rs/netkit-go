# NetKit-Go JavaScript API Reference 📜

Scripts are powered by [Goja](https://github.com/dop251/goja) — a pure Go JavaScript engine. They allow real-time traffic inspection, modification, and automation.

---

## Table of Contents

1. [Lifecycle Hooks & Globals](#1-lifecycle-hooks--globals)
2. [Context Object (`ctx`)](#2-context-object-ctx)
3. [HTTP Intelligence (`Flow`)](#3-http-intelligence-flow)
4. [Proxy & Tunneling (`Proxy`, `connect`, `Tunnel`, `CGNAT`)](#4-proxy--tunneling)
5. [Networking (`Net`, `Stack`, `DNS`, `fetch`)](#5-networking)
6. [TLS & Fingerprinting (`TLS`, `Account`)](#6-tls--fingerprinting)
7. [Security & IDS (`Security`, `IDS`)](#7-security--ids)
8. [Monitoring & Traffic (`Metrics`, `Traffic`, `Mem`)](#8-monitoring--traffic)
9. [Concurrency & Execution (`Sync`, `Runtime`, `Script`, Timers)](#9-concurrency--execution)
10. [Utilities (`Crypto`, `FS`, `MIME`, `http`, `CLI`, `Sim`)](#10-utilities)
11. [Mirror & Traffic Replay (`Mirror`)](#11-mirror--traffic-replay-️)
12. [Advanced Ad-Blocking](#12-advanced-ad-blocking-️)
13. [Metadata Keys](#13-metadata-keys-️)

---

## 1. Lifecycle Hooks & Globals

### Lifecycle Hooks

| Hook | When | Required? |
|------|------|-----------|
| `init()` | Once on script load | Optional |
| `onConnect(info)` | Connection phase (SNI/proxy handshake). Return `connect.*` to tunnel. | Optional |
| `onPacket(ctx)` | Every packet | Required (if no `onRequest`/`onResponse`) |
| `onRequest(ctx)` | HTTP requests (overrides `onPacket`) | Optional |
| `onResponse(ctx)` | HTTP responses (overrides `onPacket`) | Optional |
| `onAds(ctx)` | Every HTTP packet (ad detection) | Optional |
| `onError(err)` | Unhandled JS exceptions/panics | Optional |
| `closing()` | App shutdown | Optional |

```javascript
function init() {
    console.log("🚀 Script loaded");
    Proxy.Create({ addr: ":11080", type: "socks5" });
}

function onConnect(info) {
    console.log(`🔌 ${info.type} from ${info.ip} via ${info.through}`);
    if (info.dest.includes("blocked.com")) {
        return connect.proxy("socks5://127.0.0.1:1080");
    }
}

function onRequest(ctx) {
    console.log(`[REQ] ${ctx.FullURL}`);
}

function onResponse(ctx) {
    const body = ctx.Flow.Body().WaitFullContent();
    if (body) console.log(`[RESP] ${ctx.FullURL}: ${body.substring(0, 100)}`);
}

function onAds(ctx) {
    if (ctx.Ad && ctx.Ad.is_ad) {
        ctx.Flow.ContentType().includes("html") ? ctx.Flow.Sanitize() : ctx.Drop();
    }
}

function onError(err) { console.error(`JS ERROR: ${err}`); }
function closing() { FS.SaveFile("metrics.json", Metrics.JSON()); }
```

### Global Functions

| Function | Description |
|----------|-------------|
| `setFunc(opts)` | Dynamically enable/disable hooks. Keys: hook names, values: function name string or `false`. |
| `Reset()` | Restart JS runtime, re-executes `init()` |
| `Exit()` | Calls `closing()` then requests full process restart |
| `Domain(domain)` | Register domain for transparent interception |
| `CLI(command)` | Execute system command, returns stdout string |
| `require(path)` | CommonJS module loader (relative to script dir) |
| `runNodeJS(scriptPath)` | Bridge Node.js `module.exports` → JS engine. Returns proxy object. Requires Node.js installed. |

```javascript
// Dynamic hook control
setFunc({ onAds: false, onRequest: "myHandler" });

// Node.js bridge
const node = runNodeJS("scripts/my_node_app.js");
const token = node.sign({ user: "admin" }); // calls module.exports.sign
```

### `console` — Logging & Debugging

| Method | Description |
|--------|-------------|
| `console.log(...args)` | Print info message to stdout |
| `console.warn(...args)` | Print warning message |
| `console.error(...args)` | Print error message |
| `console.debug(...args)` | Print debug message |
| `console.time(label)` | Start a named timer |
| `console.timeEnd(label)` | Stop timer and print elapsed ms |
| `console.hexdump(data)` | Print hex dump of binary data |
| `console.packetDump(data, label)` | Print labeled hex+ASCII dump of packet data |

---

## 2. Context Object (`ctx`)

Passed to `onPacket`, `onRequest`, `onResponse`, and `onAds`.

### Actions

| Method | Description |
|--------|-------------|
| `ctx.Drop()` | Stop packet from being forwarded |
| `ctx.Bypass()` | Bypass further processing |
| `ctx.Modify(payload)` | Replace packet payload (string/bytes) |
| `ctx.Respond(payload)` | Send data back to source |
| `ctx.Send(payload, opts)` | Inject new packet. `opts`: `source`, `srcPort`, `dest`, `dstPort`, `protocol` |
| `ctx.Recv(payload)` | Modify shorthand (sets ActionModified) |
| `ctx.SetPriority(val)` | Set flow priority (0-100) |
| `ctx.Reference([val])` | Get/Set correlation UUID |

### Properties

| Property | Description |
|----------|-------------|
| `ctx.Packet` | Raw packet: `ID`, `Timestamp`, `Source`, `Dest`, `SourcePort`, `DestPort`, `Protocol`, `Payload`, `Metadata` |
| `ctx.FullURL` | Complete reconstructed HTTP URL |
| `ctx.Hostname` | SNI or Host header |
| `ctx.Ad` | Pre-detected ad result (`is_ad`, etc.) |
| `ctx.Connect` | Set to `connect.*` result for tunneling |
| `ctx.Conn` | ConnInfo: `type`, `source`, `dest`, `ip`, `through` |
| `ctx.Account` | TLS fingerprint saving and cookie persistence (requires `AccountSaver`) |
| `ctx.Session` | Persistent storage per connection |

### `onConnect` Info Object

The `info` object passed to `onConnect(info)` provides:

| Property | Description |
|----------|-------------|
| `info.Type` | Connection type (e.g. `tls`, `http`, `socks5`) |
| `info.Source` | Client address |
| `info.Dest` | Target destination (SNI / Host) |
| `info.IP` | Local listener IP |
| `info.Through` | How the connection arrived (e.g. `direct`, `socks5`) |
| `info.RemoteAddr` | Alias for `Source` |
| `info.LocalAddr` | Alias for `IP` |
| `info.LocalHost` | Alias for `Through` |

### Session (`ctx.Session`)

Persistent storage per connection: `.ID`, `.Type`, `.Src`, `.Dst`, `.Set(k,v)`, `.Get(k)`, `.Has(k)`, `.Delete(k)`, `.Keys()`, `.PacketCount()`, `.ByteCount()`, `.Duration()`, `.Metadata`.

---

## 3. HTTP Intelligence (`Flow`)

| Method | Description |
|--------|-------------|
| `Flow.ID()` | Unique connection identifier (5-tuple) |
| `Flow.Direction()` | Returns `"inbound"`, `"outbound"`, or `"unknown"` |
| `Flow.IsFirstPacket()` | Heuristic for connection initiation (TLS ClientHello or HTTP start) |
| `Flow.IsTLSHandshake()` | Payload starts with TLS handshake byte (0x16) |
| `Flow.IsTLSClientHello()` | Specifically checks for ClientHello |
| `Flow.IsTLSServerHello()` | Specifically checks for ServerHello |
| `Flow.IsHTTP()` | Protocol detection (Request or Response) |
| `Flow.IsHTTPRequest()` | HTTP request specifically (supports continuation/decrypted check) |
| `Flow.IsHTTPResponse()` | HTTP response specifically (supports continuation/decrypted check) |
| `Flow.IsWebSocket()` | Checks for WS upgrade header or binary frame |
| `Flow.IsDNS()` | Heuristic for DNS (Port 53 or DNS-like structure) |
| `Flow.IsQUIC()` | Checks for QUIC initial packets or Port 443/UDP |
| `Flow.ProtocolGuess()` | Returns `"TLS"`, `"HTTP"`, `"DNS"`, `"QUIC"`, `"WebSocket"`, `"SSH"`, `"FTP"`, `"SMTP"`, `"MySQL"`, `"PostgreSQL"`, `"Redis"`, or `"UNKNOWN"` |
| `Flow.PayloadSize()` | Length of the current packet payload |
| `Flow.ContentType()` | Content-Type header value |
| `Flow.Headers()` | Header object → `.Json()`, `.Raw()` |
| `Flow.Body()` | Smart body object (see below) |
| `Flow.UpdateBody(new)` | Replace body, auto-updates `Content-Length` |
| `Flow.Sanitize()` | Engine-level HTML ad-removal |
| `Flow.InjectJS(code)` | Prepend `<script>` tag to HTML body |
| `Flow.Snapshot()` | Unified state with fingerprints (JA3, Akamai, etc.) |
| `Flow.FullURL` | Complete reconstructed HTTP URL |
| `Flow.Protocol` / `Flow.Src` / `Flow.Dst` / `Flow.SrcPort` / `Flow.DstPort` | Direct property access |

**Body Object** (`Flow.Body()`): Direct key access for JSON/form data.
- `.IsStream()`: Returns `true` for SSE or chunked transfer.
- `.WaitFullContent()`: Buffers chunks, decompresses, and returns full string when complete.
- `.Json()`: Returns body as JSON string (or error if binary).
- `.Raw()`: Returns body as string (hex-encoded if binary).

---

## 4. Proxy & Tunneling

### `Proxy` — Dynamic MITM Listeners & Rotation

| Method | Description |
|--------|-------------|
| `Proxy.Create({ addr, type, auth })` | Start MITM proxy. Returns `{ id, connect }`. Types: `http`, `socks5`. |
| `Proxy.Drop(id)` / `Proxy.List()` | Manage listeners |
| `Proxy.AddProxy(url)` / `Proxy.Rotate()` | Proxy rotation pool |
| `Proxy.Dial(proxyURL, targetAddr, timeout)` | Low-level dialer |

```javascript
const p = Proxy.Create({ addr: ":8081", type: "socks5", auth: { user: "x", pass: "y" } });
p.connect.proxy("http://upstream:3128");  // chain upstream
```

### `connect` — Tunneling Config

Use in `onConnect` return or `ctx.Connect`. Supports chaining.

```javascript
// Proxy, WireGuard, or chained
ctx.Connect = connect.proxy("socks5://127.0.0.1:1080");
ctx.Connect = connect.wg("... wg config ...");
ctx.Connect = connect.proxy("http://proxy:8080").wg("...");

// SSH tunnel
ctx.Connect = connect.ssh({ host: "example.com", port: 22, user: "root", pass: "secret" });
ctx.Connect = connect.ssh({ host: "example.com", user: "root", key: "~/.ssh/id_rsa" });

// CGNAT auto-bypass
ctx.Connect = connect.cgnat();  // auto-detect
ctx.Connect = connect.cgnat({ relay: "relay.example.com:9090", auth: "token123" });
```

**`connect.ssh(opts)`** — SSH tunnel with options:

| Option | Description |
|--------|-------------|
| `host` | SSH server hostname |
| `port` | SSH port (default: `22`) |
| `user` | SSH username |
| `pass` | SSH password |
| `key` | Path to SSH private key |

**`connect.cgnat(opts)`** — CGNAT auto-bypass tunnel:

| Option | Description |
|--------|-------------|
| `relay` | Relay server address |
| `auth` | Authentication token |
| `mikrotik_host` | MikroTik API host |
| `mikrotik_user` | MikroTik username |
| `mikrotik_pass` | MikroTik password |
| `auto_detect` | Auto-detect NAT type (default: `true`) |

### `Tunnel` — NK-Tunnel (Self-hosted) & SSH Forwarding

| Method | Description |
|--------|-------------|
| `Tunnel.CreateServer({ addr, portRange, user, pass })` | Start NK-Tunnel server |
| `Tunnel.Connect({ server, user, pass, local, remote, proto, ssh })` | Start NK-Tunnel client. Port exposed on **NK-Tunnel Server IP**. |
| `Tunnel.SSHReverse({ local, remote, ssh })` | SSH reverse port forwarding (`ssh -R`). Port exposed on **SSH Server IP**. TCP only. |

**`Tunnel.CreateServer` Options:**

| Option | Description |
|--------|-------------|
| `addr` | Listen address (e.g. `":9090"`) |
| `portRange` | Port range for public ports (e.g. `"8000-8010"`) |
| `user` | Auth username |
| `pass` | Auth password |

**`Tunnel.Connect` Options:**

| Option | Description |
|--------|-------------|
| `server` | NK-Tunnel server address (e.g. `"vps.example.com:9090"`) |
| `user` / `pass` | NK-Tunnel auth credentials |
| `local` | Local address to forward to (e.g. `"127.0.0.1:3000"`) |
| `remote` | Public port or range on server (e.g. `"8000"` or `"8000-8010"`) |
| `proto` | Protocol: `"tcp"` (default) or `"udp"` |
| `ssh` | Optional SSH transport config (see below). Control connection routes through SSH. |

**`Tunnel.SSHReverse` Options:**

| Option | Description |
|--------|-------------|
| `local` | Local address to forward to (e.g. `"127.0.0.1:3000"`) |
| `remote` | Bind address on SSH server (e.g. `"0.0.0.0:8080"`) |
| `ssh` | SSH connection config (required, see below) |

**SSH Config** (used in both `Tunnel.Connect` and `Tunnel.SSHReverse`):

| SSH Option | Description |
|------------|-------------|
| `host` | SSH server hostname |
| `port` | SSH port (default: `22`) |
| `user` | SSH username |
| `pass` | SSH password |
| `key` | Path to SSH private key or raw PEM |

```javascript
// ── NK-Tunnel (direct) ──
// Public port on NK-Tunnel Server IP
Tunnel.Connect({
    server: "vps.example.com:9090",
    user: "admin", pass: "secret",
    local: "127.0.0.1:3000",       // local service
    remote: "8000",                 // public port on server
    proto: "tcp"
});

// ── NK-Tunnel via SSH transport ──
// Control connection encrypted via SSH
Tunnel.Connect({
    server: "127.0.0.1:9090",      // NK-Server (from SSH perspective)
    user: "admin", pass: "secret",
    local: "127.0.0.1:3000",
    remote: "8000",
    proto: "tcp",
    ssh: { host: "vps.example.com", port: 22, user: "root", pass: "sshpass" }
});

// ── SSH Reverse Forwarding (ssh -R) ──
// No NK-Tunnel Server needed, port on SSH server IP
Tunnel.SSHReverse({
    local: "127.0.0.1:3000",
    remote: "0.0.0.0:8080",
    ssh: { host: "vps.example.com", port: 22, user: "root", pass: "sshpass" }
});
// Access: http://vps.example.com:8080
```


### `CGNAT` — NAT Detection & Bypass

| Method | Description |
|--------|-------------|
| `CGNAT.Detect()` | Auto-detect → `{ natType, canHolePunch, networkType, publicIP, localIP, isp, routerType, strategy, latencyMs, upnpMapped }` |
| `CGNAT.Execute(port)` | Run bypass → `{ success, strategy, publicIP, publicPort, error }` |
| `CGNAT.SetRelay(addr, token)` | Configure relay for symmetric NAT |
| `CGNAT.SetTunnel(server, user, pass)` | Configure NK-Tunnel for bypass |
| `CGNAT.GetPublicEndpoint()` | Returns `{ ip, port, endpoint }` after Execute |
| `CGNAT.Interfaces()` | List network interfaces → `[{ name, ipv4, type, mtu, docker }]` |
| `CGNAT.MikroTik(host, user, pass)` | MikroTik helper → `AddPortForward(ext, int, ip, proto)`, `RemovePortForward()`, `EnableUPnP()` |

```javascript
function init() {
    const info = CGNAT.Detect();
    console.log(`NAT: ${info.natType}, ISP: ${info.isp}`);
    if (!info.canHolePunch) CGNAT.SetTunnel("tunnel.example.com:9090", "admin", "secret");
    const res = CGNAT.Execute(8080);
    if (res.success) console.log(`Public: ${res.publicIP}:${res.publicPort}`);
}
```

---

## 5. Networking

### `Net` — TCP/UDP Sockets

| Method | Description |
|--------|-------------|
| `Net.Dial(address, timeoutMs)` / `Net.DialTCP(address, timeoutMs)` | TCP connection |
| `Net.DialUDP(address)` | UDP connection |
| `Net.Listen(address)` | TCP listener → `{ Accept(), Close(), Addr() }` |
| `Net.RawSend(address, data)` | Fire-and-forget UDP |
| `Net.DialRaw(protocol)` | Raw IP socket with `IP_HDRINCL` → `{ Write(header, payload), Read(), Close() }` |

**Connection Object**: `.Read(size)`, `.ReadAll()`, `.Write(data)`, `.WriteString(s)`, `.Close()`, `.CloseWrite()`, `.CloseRead()`, `.SetDeadline(ms)`, `.SetReadDeadline(ms)`, `.SetWriteDeadline(ms)`, `.SetKeepAlive(bool)`, `.SetKeepAlivePeriod(sec)`, `.SetNoDelay(bool)`, `.SetLinger(sec)`, `.LocalAddr()`, `.RemoteAddr()`.

### `Stack` — Raw Packet Crafting & Inspection

| Method | Description |
|--------|-------------|
| `Stack.NewIPv4(src, dst, proto)` / `Stack.NewTCP(srcPort, dstPort)` | Create header structs |
| `Stack.Hexdump(data)` / `Stack.HexEncode(data)` / `Stack.HexDecode(s)` | Encoding |
| `Stack.ReadTTL(data)` / `Stack.SetTTL(data, ttl)` | IPv4 TTL |
| `Stack.ReadIPProtocol(data)` | IP protocol number |
| `Stack.ReadSrcIP(data)` / `Stack.ReadDstIP(data)` | IPv4 addresses |
| `Stack.ReadSrcPort(data)` / `Stack.ReadDstPort(data)` | TCP/UDP ports |
| `Stack.ReadTCPFlags(data)` / `Stack.SetTCPFlags(data, flags)` | TCP flags → `{ SYN, ACK, FIN, RST, PSH, URG, ECE, CWR, raw }` |
| `Stack.ReadWindowSize(data)` | TCP window size |
| `Stack.IsECN(data)` / `Stack.IsFragmented(data)` | IP header checks |

### `DNS` — Lookups

| Method | Description |
|--------|-------------|
| `DNS.Lookup(host)` | Resolve A/AAAA records |
| `DNS.Reverse(ip)` | PTR lookup |
| `DNS.AsyncPTR(ip)` | Async PTR → result in `onPacket` with `Metadata.IsPtrResponse` |
| `FetchAsync(url, opts)` | Async fetch → result in `onPacket` with `Metadata.IsFetchResponse` |

### `fetch(url, options)` — HTTP Requests

```javascript
const resp = await fetch("https://ipinfo.io/json", { method: "GET", profile: "chrome_120" });
// resp: { status, ok, headers, body, bodyBytes }
```

---

## 6. TLS & Fingerprinting

### `TLS` — Analysis & Manipulation

| Method | Description |
|--------|-------------|
| `TLS.IsTLS(data)` / `TLS.IsClientHello(data)` / `TLS.IsServerHello(data)` | Detection |
| `TLS.ExtractSNI(data)` / `TLS.ExtractALPN(data)` | Extract fields from ClientHello |
| `TLS.GetVersion(data)` | Version string (`TLS 1.2`, `TLS 1.3`, etc.) |
| `TLS.GetRecordType(data)` | `ChangeCipherSpec`, `Alert`, `Handshake`, `Application` |
| `TLS.GetHandshakeType(data)` | `ClientHello`, `ServerHello`, `Certificate`, etc. |
| `TLS.ParseClientHello(data)` / `TLS.ReconstructClientHello(ch)` | Full parse/rebuild |
| `TLS.RewriteSNI(data, newSNI)` | Replace SNI in ClientHello |

### `Account` — TLS Fingerprint Persistence

Available when `AccountSaver` is attached.

| Method | Description |
|--------|-------------|
| `Account.SaveTLS(ja3, ja4, ja3s, ja4s, akamai, cloudflare)` | Persist TLS fingerprints |
| `Account.SaveCookie(name, value)` / `Account.SaveToken(token)` / `Account.SaveUA(ua)` | Save credentials |
| `Account.ComputeClientHello(bytes)` / `Account.ComputeServerHello(bytes)` | Process Hello for fingerprinting |

```javascript
function onPacket(ctx) {
    const payload = ctx.Packet.Payload;
    if (TLS.IsClientHello(payload)) {
        console.log(`[TLS] ${TLS.ExtractSNI(payload)} — ${TLS.GetVersion(payload)}`);
    }
}
```

---

## 7. Security & IDS

### `Security` — Permissions & Resource Limits

| Method | Description |
|--------|-------------|
| `Security.GetPermissions()` | Returns current permission map |
| `Security.CheckPermission(perm)` | Check specific permission (e.g., `net.dial`, `fs.read`) |
| `Security.SetPermission(p, bool)` | Enable/disable a permission scope |
| `Security.GetLimits()` | Returns `{ maxMemoryMB, maxCPUMs, maxLoopIters, panicRecover }` |
| `Security.SetMaxMemory(mb)` | Set memory limit (default: 256MB) |
| `Security.SetMaxCPU(ms)` | Set max execution time per call (default: 5000ms) |
| `Security.SetMaxLoopIters(n)` | Infinite loop guard threshold (default: 1M) |

#### Advanced Security Modules

**`Security.Firewall`** (Engine-level rules)
- `.AddRule(rule)`: Add `FirewallRule` object (`name`, `priority`, `action` ["ALLOW"/"DENY"/"LOG"], `direction` ["IN"/"OUT"/"BOTH"], `srcIP`, `dstIP`, `srcPort`, `dstPort`, `protocol`).
- `.RemoveRule(name)`: Remove rule by name.
- `.ListRules()`: Return array of all active rules.

**`Security.Scope`** (Network Role Awareness)
- `.GetRole()`: Returns current role (`Client`, `Server`, `Both`).
- `.SetRole(role)`: Set active role.
- `.GetActiveScope()`: Returns current scope level.
- `.SetScope(lvl, ttl, reason)`: Set absolute or temporary scope with TTL.

**`Security.Bruteforce`** (IP Protection)
- `.GetBannedIPs()`: List all IPs currently blocked by the limiter.
- `.UnbanIP(ip)`: Manually remove an IP from the blacklist.

### `IDS` — Intrusion Detection

**Pattern & Regex Matching:**

| Method | Description |
|--------|-------------|
| `IDS.PatternMatch(data, pattern)` | Check if payload contains byte pattern |
| `IDS.PatternMatchString(d, s)` | Check if payload contains string |
| `IDS.RegexMatch(data, pattern)` | Boolean regex match |
| `IDS.RegexFind(data, pattern)` | Returns array of all string matches |
| `IDS.RegexReplace(d, p, r)` | Replace matches returning modified bytes |
| `IDS.ContainsAny(d, patterns)` | Efficient multiple pattern check |
| `IDS.CountOccurrences(d, p)` | Returns count of pattern matches |
| `IDS.IndexOf(d, p)` | First index of pattern in payload |
| `IDS.Entropy(payload)` | Shannon entropy (0-8). High value (>7.5) indicates encryption. |

**Signature Engine:**

| Method | Description |
|--------|-------------|
| `IDS.AddSignature(id, name, pattern, regex, action)` | Register a rule. Actions: `alert`, `drop`, `log`. |
| `IDS.RemoveSignature(id)` | Delete rule by ID |
| `IDS.ScanPayload(payload)` | Batch scan against all rules → `[{ id, name, action }]` |
| `IDS.ListSignatures()` | List all active signatures |
| `IDS.ClearSignatures()` | Remove all signatures |

```javascript
function init() {
    IDS.AddSignature("sql-1", "SQL Injection", null, "(?i)(union\\s+select|drop\\s+table)", "alert");
    Security.SetMaxCPU(3000);
    Security.SetPermission("exec.spawn", false);
}

function onRequest(ctx) {
    const matches = IDS.ScanPayload(ctx.Packet.Payload);
    for (const m of matches) {
        if (m.action === "drop") { ctx.Drop(); return; }
    }
}
```

---

## 8. Monitoring & Traffic

### `Metrics` — Telemetry Counters

| Method | Description |
|--------|-------------|
| `Metrics.IncrPackets(n)` / `Metrics.GetPackets()` | Packet count |
| `Metrics.IncrBytes(n)` / `Metrics.GetBytes()` | Byte count |
| `Metrics.IncrDropped()` / `Metrics.GetDropped()` | Dropped packets |
| `Metrics.IncrModified()` / `Metrics.GetModified()` | Modified packets |
| `Metrics.IncrConns()` / `Metrics.DecrConns()` / `Metrics.GetActiveConns()` | Active connections |
| `Metrics.Uptime()` / `Metrics.UptimeMs()` / `Metrics.PPS()` / `Metrics.BPS()` | Performance stats |
| `Metrics.SetCustom(name, val)` / `Metrics.IncrCustom(name, n)` / `Metrics.GetCustom(name)` | Custom counters |
| `Metrics.Snapshot()` / `Metrics.JSON()` / `Metrics.Reset()` | Export / reset |

### `Traffic` — Rate Limiting, Throttling, Flood Detection

| Method | Description |
|--------|-------------|
| `Traffic.RateLimit(key, rps)` / `Traffic.RateLimitN(key, rps, n)` | Token bucket rate limiter |
| `Traffic.ResetRateLimit(key)` / `Traffic.ResetAllRateLimits()` | Reset limiters |
| `Traffic.SetMaxConnections(max)` / `Traffic.ConnectionAllowed()` / `Traffic.ActiveConnections()` | Connection limits |
| `Traffic.IncrementConnections()` / `Traffic.DecrementConnections()` | Track connections |
| `Traffic.SetThrottle(bps)` / `Traffic.GetThrottle()` / `Traffic.ThrottleCheck(dataSize)` / `Traffic.AddBandwidth(bytes)` | Bandwidth throttling |
| `Traffic.SetFloodThreshold(pps)` / `Traffic.FloodCheck()` | Flood detection |

### `Mem` — Memory Management

| Method | Description |
|--------|-------------|
| `Mem.Reduce()` | System-level memory optimization (Windows: trims working set) |
| `Mem.StartPeriodic(intervalMs)` | Periodic reduction (default: 60s) |
| `Mem.GC()` / `Mem.FreeOSMemory()` | Garbage collection |
| `Mem.SetGCPercent(percent)` / `Mem.SetMemoryLimit(mb)` | GC tuning |
| `Mem.Stats()` | Full stats: `allocMB`, `heapAllocMB`, `numGC`, `numGoroutine`, etc. |
| `Mem.HeapAlloc()` / `Mem.NumGoroutine()` | Quick stats |

```javascript
function onPacket(ctx) {
    Metrics.IncrPackets(1);
    Metrics.IncrBytes(ctx.Packet.Payload.length);

    if (!Traffic.RateLimit(ctx.Packet.Source, 100)) {
        ctx.Drop();
        Metrics.IncrDropped();
    }
}

function init() {
    Mem.StartPeriodic(30000);
    Mem.SetMemoryLimit(256);

    const app = http.createServer();
    app.get("/metrics", (req, res) => res.json(Metrics.Snapshot()));
    app.listen(8081);
}
```

---

## 9. Concurrency & Execution

### `Sync` — Go-powered Concurrency Primitives

| Factory | Description |
|---------|-------------|
| `Sync.NewMutex()` | Mutual exclusion lock: `.Lock()`, `.Unlock()` |
| `Sync.NewRWMutex()` | Read/Write lock: `.Lock()`, `.Unlock()`, `.RLock()`, `.RUnlock()` |
| `Sync.NewAtomic(initial)` | Atomic operations (number/bool): `.Get()`, `.Set(v)`, `.Add(d)`, `.Incr()`, `.Decr()`, `.CompareAndSwap(o, n)` |
| `Sync.NewOnce()` | One-time execution: `.Do(fn)` |
| `Sync.NewChannel(size)` | Goroutine-safe channels: `.Send(v)`, `.Receive()`, `.ReceiveBlocking()`, `.Len()`, `.Cap()`, `.Close()` |
| `Sync.NewWaitGroup()` | Wait for goroutines: `.Add(n)`, `.Done()`, `.Wait()` |
| `Sync.NewWorkerPool(count)` | Fixed-size worker pool: `.Submit(fn)`, `.Stop()`, `.QueueSize()` |
| `Sync.NewEventBus()` | Pub/Sub system: `.On(event, handler)`, `.Emit(event, data)`, `.Off(event)`, `.Events()` |
| `Sync.NewMap()` | Thread-safe key-value store: `.Set(k,v)`, `.Get(k)`, `.Delete(k)`, `.Has(k)`, `.Keys()` |

### `Runtime` & `Script` — Goroutines & Rule Management

| Method | Description |
|--------|-------------|
| `Runtime.spawn(fn)` | Run function in background goroutine → returns ID |
| `Runtime.spawnWithTimeout(fn, ms)` | Spawn with deadline |
| `Script.RegisterRule(id, name, priority, tags)` | Register named rule |
| `Script.EnableRule(id)` / `Script.DisableRule(id)` / `Script.IsEnabled(id)` | Toggle rules |
| `Script.SetPriority(id, priority)` / `Script.SetTimeout(id, ms)` / `Script.SetMemLimit(id, mb)` | Rule config |
| `Script.ListRules()` / `Script.RemoveRule(id)` / `Script.GetRulesByTag(tag)` | Rule management |

### Timers

| Function | Description |
|----------|-------------|
| `setTimeout(fn, ms)` / `clearTimeout(id)` | One-shot timer |
| `setInterval(fn, ms)` / `clearInterval(id)` | Repeating timer |
| `Sleep(ms)` | Blocking sleep |

```javascript
function init() {
    const bus = Sync.NewEventBus();
    bus.On("alert", (data) => console.log("Alert:", data));

    Runtime.spawn(() => {
        while (true) {
            Sleep(5000);
            bus.Emit("alert", { heap: Mem.HeapAlloc() });
        }
    });

    Script.RegisterRule("logger", "Traffic Logger", 5, ["monitoring"]);
}
```

---

## 10. Utilities

### `Crypto` — Hashing, Encryption, Encoding

| Method | Description |
|--------|-------------|
| `Crypto.SHA256(data)` / `Crypto.SHA1(data)` / `Crypto.SHA512(data)` / `Crypto.MD5(data)` | Hash → hex string |
| `Crypto.SHA256Bytes(data)` | Hash → raw bytes |
| `Crypto.HMAC(algo, key, data)` | HMAC (`sha256`/`sha1`/`sha512`/`md5`) → hex |
| `Crypto.AESEncrypt(key, plaintext)` | AES-GCM encrypt. Returns `{ ciphertext, nonce }`. |
| `Crypto.AESDecrypt(key, nonce, ciphertext)` | AES-GCM decrypt. Returns plaintext bytes. |
| `Crypto.XOR(data, key)` | XOR with repeating key |
| `Crypto.Base64Encode(data)` / `Crypto.Base64Decode(s)` | Standard Base64 |
| `Crypto.Base64URLEncode(data)` / `Crypto.Base64URLDecode(s)` | URL-safe Base64 |
| `Crypto.HexEncode(data)` / `Crypto.HexDecode(s)` | Hex encoding |
| `Crypto.RandomBytes(n)` | Generate `n` cryptographically secure random bytes |
| `Crypto.RandomHex(n)` | Generate `n` random bytes as hex string |

### `FS` — File System & Shared Cache

| Method | Description |
|--------|-------------|
| `FS.Read(path)` / `FS.ReadString(path)` | Read files |
| `FS.SaveFile(path, data)` | Write files |
| `FS.SetCache(key, value)` / `FS.GetCache(key)` | Global shared cache (persists across sessions) |
| `FS.Decompress(bytes, encoding)` | Manual decompression (gzip/deflate/br) |
| `FS.Data()` | JSON array of last N packet snapshots |
| `FS.SetDataLimit(limit)` | Max historical entries (default: 100) |

### `MIME` — Content-Type Detection

| Method | Description |
|--------|-------------|
| `MIME.Detect(data)` | Auto-detect → `{ type, category, isText }` (magic bytes + heuristics) |
| `MIME.GetInfo(mimeType)` | Get info → `{ type, category, isText }` |
| `MIME.IsText(mimeType)` / `MIME.IsBinary(mimeType)` | Type checks |

**Categories**: `TEXT`, `APPLICATION`, `IMAGE`, `AUDIO`, `VIDEO`, `FONT`, `MULTIPART`, `STREAMING`, `RPC / PROTOBUF / BINARY API`, `BINARY STRUCTURED`.

### `http` — Express-like HTTP Server

```javascript
const app = http.createServer();
app.use((req, res, next) => { console.log(`${req.method} ${req.path}`); next(); });
app.get("/status", (req, res) => res.status(200).json({ ok: true }));
app.post("/data", (req, res) => { console.log(req.bodyString); res.json({ received: true }); });
app.put("/update", handler);
app.delete("/remove", handler);
app.listen(8080);
```

**`req`**: `method`, `url`, `path`, `headers`, `body`, `bodyString`.  
**`res`** (chainable): `.status(code)`, `.json(data)`, `.send(data)`, `.setHeader(k,v)`.  
**Note**: All responses include `X-Powered-By: NetKit`.

### `Sim` — Network Simulation (Testing)

| Method | Description |
|--------|-------------|
| `Sim.Delay(ms)` / `Sim.RandomDelay(min, max)` / `Sim.Jitter(mean, stddev)` | Latency simulation |
| `Sim.ShouldDrop(prob)` / `Sim.ShouldCorrupt(prob)` / `Sim.ShouldDuplicate(prob)` | Probability-based events (0.0-1.0) |
| `Sim.CorruptBytes(data, n)` | Randomly corrupt n bytes |
| `Sim.Fragment(data, mtu)` | Split into MTU chunks |
| `Sim.Reorder(packets)` | Shuffle packet array |
| `Sim.Throttle(bps, dataSize)` | Simulate bandwidth limit |

## 11. Mirror & Traffic Replay (`Mirror`) ️

Available as `ctx.Mirror` for recording, replaying, and cloning packets.

| Method | Description |
|--------|-------------|
| `Mirror.Tee(payload)` | Passive clone: copy current packet payload to the engine |
| `Mirror.Record(flowID, payload, direction)` | Store a packet for later replay |
| `Mirror.GetRecording(flowID)` | Return all recorded packets for a flow |
| `Mirror.Replay(flowID)` | Replay recorded packets with original timing |
| `Mirror.ClearRecording(flowID)` | Remove a flow recording |
| `Mirror.ClearAll()` | Clear all recordings |
| `Mirror.ListRecordings()` | List flow IDs and packet counts |
| `Mirror.SaveRaw(flowID, path)` | Export recorded flow to a raw binary file |

---

## 12. Advanced Ad-Blocking 🛡️

```javascript
function onAds(ctx) {
    const url = ctx.FullURL;

    // 1. Engine-detected ads
    if (ctx.Ad && ctx.Ad.is_ad) {
        ctx.Flow.ContentType().includes("html") ? ctx.Flow.Sanitize() : ctx.Drop();
        return;
    }

    // 2. YouTube ads
    if (url.includes("/ptrack/") || url.includes("/adunit") || url.includes("/api/stats/ads")) {
        ctx.Drop();
        return;
    }
    if (url.includes("youtubei/v1/player")) {
        let body = ctx.Flow.Body().Json();
        if (body.includes("adPlacements")) {
            ctx.Flow.UpdateBody(body.replace(/"adPlacements":\[.*?\]/g, '"adPlacements":[]'));
        }
    }

    // 3. Universal HTML sanitization
    if (ctx.Flow.IsHTTPResponse() && ctx.Flow.ContentType().includes("html")) {
        ctx.Flow.Sanitize();
    }
}
```

---

## 13. Metadata Keys 🏷️

All keys in `ctx.Packet.Metadata` use **PascalCase**.

| Key | Description |
|-----|-------------|
| `Reference` | Correlation UUID for request/response pair |
| `Hostname` | SNI or Host header value |
| `JA3Hash` / `JA3String` | JA3 TLS fingerprint |
| `Transparent` | `true` if captured via transparent interception |
| `Decrypted` | `true` if packet was decrypted via MITM interception |
| `Direction` | `"REQUEST"` or `"RESPONSE"` |
| `IsPtrResponse` | `true` for async DNS reverse lookups |
| `IsFetchResponse` | `true` for async HTTP fetch results |
| `Ad` | Ad detection results (`is_ad`, `matches`, etc.) |