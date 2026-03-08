// ============================================================
// SSH Reverse Tunnel Script — Port Forwarding via SSH
// ============================================================
// Expose local service langsung di IP SSH server
// Tidak perlu NK-Tunnel Server sama sekali!
//
// Cara pakai:
//   go run main.go --script scripts/ssh_tunnel.js
//
// Flow:
//   Internet → SSH_IP:80 → SSH Reverse Forward → Lokal:5500
// ============================================================

function init() {
    console.log("🚀 SSH Reverse Tunnel Script loaded");

    // ── 1. Start local HTTP API for monitoring ──
    const app = http.createServer();
    app.get("/api/status", (req, res) => {
        res.json({
            status: "running",
            uptime: Metrics.Uptime(),
            packets: Metrics.GetPackets(),
            bytes: Metrics.GetBytes(),
            activeConns: Metrics.GetActiveConns(),
            memory: Mem.Stats()
        });
    });
    app.listen(3000);
    console.log("📊 API server listening on :3000");

    // ── 2. SSH Reverse Tunnel ──
    // Ini akan:
    //   1. SSH ke 43.163.104.79:22
    //   2. Bind port 80 di SSH server (0.0.0.0:80)
    //   3. Forward semua koneksi dari SSH_IP:80 ke local:5500
    Tunnel.SSHReverse({
        local: "127.0.0.1:3000",       // Local service
        remote: "0.0.0.0:1080",          // Bind on SSH server (port 80)
        ssh: {
            host: "43.163.104.79",
            port: 22,
            user: "ubuntu",
            pass: "vkf4zmKifvcEUD6"
        }
    });

    console.log("🔑 SSH Reverse Tunnel starting...");
    console.log("   SSH: ubuntu@43.163.104.79:22");
    console.log("   Remote bind: 0.0.0.0:80");
    console.log("   Forward to: 127.0.0.1:5500");
    console.log("   Access: http://43.163.104.79:80");

    // ── 3. Periodic status logging ──
    setInterval(() => {
        const stats = Mem.Stats();
        console.log(`📈 Uptime: ${Metrics.Uptime()} | Packets: ${Metrics.GetPackets()} | Mem: ${stats.allocMB}MB`);
    }, 30000);
}

function onConnect(info) {
    console.log(`🔌 ${info.type} from ${info.ip} → ${info.dest}`);
}

function onRequest(ctx) {
    console.log(`📥 [REQ] ${ctx.FullURL}`);
    Metrics.IncrPackets(1);
}

function onResponse(ctx) {
    const body = ctx.Flow.Body().WaitFullContent();
    if (body) {
        console.log(`📤 [RESP] ${ctx.FullURL}: ${body.substring(0, 80)}...`);
    }
    Metrics.IncrPackets(1);
}

function onError(err) {
    console.error(`❌ Error: ${err}`);
}

function closing() {
    console.log("👋 SSH Reverse Tunnel Script shutting down");
}
