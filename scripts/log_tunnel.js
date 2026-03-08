// log_tunnel.js - Monitoring NK-Tunnel Activity
// This script focuses on Tunnel Client and Server connections.

function init() {
    console.log("🏰 NK-Tunnel Logger Active");
    console.log("Monitoring encrypted tunnels and remote port forwardings.");

    // Example: Start a Tunnel Server
    /*
    Tunnel.CreateServer({
        addr: ":11082",
        portRange: "20000-30000",
        user: "admin",
        pass: "password"
    });
    */

    // Example: Connect to a Remote Tunnel

    Tunnel.Connect({
        server: "157.15.40.76:11080",
        user: "admin",
        pass: "secret",
        local: "127.0.0.1:1080",
        remote: "127.0.0.1:1080",
        proto: "tcp|udp"
    });
}

/**
 * onConnect identifies when a tunnel client connect to us (if we are server)
 * or when we connect as a client to a remote tunnel.
 */
function onConnect(conn) {
    console.log(JSON.stringify(conn))
    console.log(`🔌 [${conn.type}] ${conn.source} → ${conn.dest}`);
    // Return nothing = pass-through (no MITM, no SSL error)
}

/**
 * onPacket allows inspecting raw data flowing through the tunnel.
 * If the tunnel is decrypted (at the end-point), you can see the payload.
 */
function onPacket(ctx) {
    if (ctx.Conn && (ctx.Conn.type === "tunnelclient" || ctx.Conn.type === "server")) {
        // Log a small snippet of data for tunnel visibility
        // console.log(`[Tunnel] 📦 Data transfer: ${ctx.Packet.Payload.length} bytes`);
    }
}

function closing() {
    console.log("Shutting down Tunnel Logger.");
}
