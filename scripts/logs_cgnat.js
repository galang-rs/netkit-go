// logs_cgnat.js - CGNAT Detection & Tunnel Bypass
// Detects NAT type, connects tunnel, tests port accessibility, returns publicIP:port.

function init() {
    console.log("═══════════════════════════════════════════════════════");
    console.log("  🌐 NetKit CGNAT Detector + Tunnel Bypass");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    // ───────────── 1. List Network Interfaces ─────────────
    console.log("📡 Network Interfaces:");
    console.log("───────────────────────────────────────────────────────");
    var ifaces = ctx.CGNAT.Interfaces();
    for (var i = 0; i < ifaces.length; i++) {
        var iface = ifaces[i];
        var icon = "🔌";
        if (iface.type === "WiFi") icon = "📶";
        if (iface.type === "Mobile") icon = "📱";
        if (iface.type === "Ethernet") icon = "🖧";
        if (iface.type === "VPS") icon = "☁️";
        if (iface.docker) icon = "🐳";

        console.log("  " + icon + " " + iface.name);
        console.log("       IPv4: " + (iface.ipv4 || "N/A"));
        console.log("       Type: " + iface.type);
        console.log("       MTU:  " + iface.mtu);
        if (iface.docker) {
            console.log("       ⚠️  Docker/Container interface (skip)");
        }
        console.log("");
    }

    // ───────────── 2. NAT Detection via STUN ─────────────
    console.log("🔍 Detecting NAT Type...");
    console.log("───────────────────────────────────────────────────────");
    var result = ctx.CGNAT.Detect();

    console.log("  NAT Type:     " + result.natType);
    console.log("  Network:      " + result.networkType);
    console.log("  Public IP:    " + result.publicIP);
    console.log("  Public Port:  " + result.publicPort);
    console.log("  Local IP:     " + result.localIP);
    console.log("  ISP:          " + result.isp);
    console.log("  Router:       " + result.routerType);
    console.log("  Latency:      " + result.latencyMs + "ms");
    console.log("  UPnP Mapped:  " + result.upnpMapped);
    console.log("  Hole Punch:   " + (result.canHolePunch ? "✅ Possible" : "❌ Not possible"));
    console.log("  Strategy:     " + result.strategy);
    console.log("");

    // ───────────── 3. Analysis ─────────────
    console.log("📋 Analysis:");
    console.log("───────────────────────────────────────────────────────");

    var isCGNAT = false;
    if (result.isp === "CGNAT") {
        isCGNAT = true;
        console.log("  ⚠️  IP " + result.publicIP + " is in CGNAT range (100.64.0.0/10)");
        console.log("     → ISP sharing this IP with other customers");
    } else if (result.isp === "Private") {
        isCGNAT = true;
        console.log("  ⚠️  IP " + result.publicIP + " is a private IP (double NAT)");
    }

    if (result.natType === "No NAT (Direct)") {
        console.log("  ✅ Kamu punya IP publik langsung!");
        console.log("     → IP: " + result.publicIP);
    }

    if (result.natType === "Symmetric NAT") {
        console.log("  ❌ Symmetric NAT — butuh reverse tunnel");
    }

    if (result.natType === "Port-Restricted Cone NAT") {
        console.log("  ⚠️  Port-Restricted — tunnel recommended");
    }

    if (result.natType === "UDP Blocked") {
        console.log("  ❌ UDP blocked — hanya TCP tunnel yang bisa");
    }
    console.log("");

    // ───────────── 4. Tunnel Bypass ─────────────
    // Jika butuh tunnel, configure dan execute
    if (result.natType !== "No NAT (Direct)") {
        console.log("🚀 Attempting CGNAT Bypass via NK-Tunnel...");
        console.log("───────────────────────────────────────────────────────");

        // Configure tunnel server (ubah ke IP VPS kamu)
        // ctx.CGNAT.SetTunnel("VPS_IP:9000", "admin", "password");

        // Execute bypass pada port 8080
        // var bypass = ctx.CGNAT.Execute(8080);
        // if (bypass.success) {
        //     console.log("  ✅ Tunnel Connected!");
        //     console.log("  Strategy:     " + bypass.strategy);
        //     console.log("  Public IP:    " + bypass.publicIP);
        //     console.log("  Public Port:  " + bypass.publicPort);
        //     console.log("");
        //     console.log("  ╔═══════════════════════════════════════════╗");
        //     console.log("  ║  🌍 PUBLIC ENDPOINT:                     ║");
        //     console.log("  ║  " + bypass.publicIP + ":" + bypass.publicPort);
        //     console.log("  ║                                           ║");
        //     console.log("  ║  External clients can now connect to:     ║");
        //     console.log("  ║  http://" + bypass.publicIP + ":" + bypass.publicPort);
        //     console.log("  ╚═══════════════════════════════════════════╝");
        // } else {
        //     console.log("  ❌ Bypass failed: " + bypass.error);
        // }

        console.log("  ⚠️ Tunnel server belum dikonfigurasi.");
        console.log("  Uncomment kode di atas dan set VPS IP:");
        console.log("");
        console.log("  ctx.CGNAT.SetTunnel('VPS_IP:9000', 'user', 'pass');");
        console.log("  var result = ctx.CGNAT.Execute(8080);");
        console.log("  // result.publicIP + ':' + result.publicPort");
        console.log("");
        console.log("  Atau pakai Tunnel.Connect langsung:");
        console.log("  ctx.Tunnel.Connect({");
        console.log("      server: 'VPS_IP:9000',");
        console.log("      user: 'admin', pass: 'password',");
        console.log("      local: '127.0.0.1:8080',");
        console.log("      remote: '10000', proto: 'tcp'");
        console.log("  });");
    }

    console.log("");
    console.log("═══════════════════════════════════════════════════════");
}

function onConnect(conn) {
    // Log tunnel connection events
    if (conn.type === "tunnelclient" || conn.type === "server") {
        console.log("[CGNAT-Tunnel] 🔗 " + conn.type + ": " + conn.source + " → " + conn.dest);
    }
}

function onPacket(ctx) {
    // Monitor tunnel packets if needed
}

function closing() {
    console.log("🌐 CGNAT Detector stopped.");
}
