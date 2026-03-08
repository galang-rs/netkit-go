// log_socks.js - Dedicated SOCKS5 Connection Logging
// This script monitors SOCKS5 proxy activity.

function init() {
    console.log("🚀 SOCKS5 Logger Active");
    console.log("Monitoring SOCKS5 traffic in real-time.");

    // Example: Start a SOCKS5 Proxy
    /*
    Proxy.Create({
        addr: ":11080",
        type: "socks5",
    });
    */
}

/**
 * onConnect is triggered when a new client connects to any listener.
 * @param {object} conn - Connection metadata
 */
function onConnect(conn) {
    if (conn.type === "socks5") {
        console.log(`[SOCKS5] 🔌 New Connection:`);
        console.log(`       - Source:  ${conn.source}`);
        console.log(`       - Dest:    ${conn.dest}`);
        console.log(`       - Client:  ${conn.ip}`);
        console.log(`       - Through: ${conn.through}`); // Identifies if localhost/private/public
    }
}

/**
 * onPacket is triggered for every raw packet.
 * We can filter for SOCKS5 tagged packets.
 */
function onPacket(ctx) {
    if (ctx.Conn && ctx.Conn.type === "socks5") {
        // Only log if we have a hostname (from MITM or SNI)
        const hostname = ctx.Packet.Metadata?.Hostname || "unknown";
        if (hostname !== "unknown") {
            // console.log(`[SOCKS5] 📦 Data for ${hostname} (${ctx.Packet.Payload.length} bytes)`);
        }
    }
}

function closing() {
    console.log("Shutting down SOCKS5 Logger.");
}
