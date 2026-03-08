// log_server.js - Monitoring Built-in HTTP Server
// This script demonstrates the built-in HTTP server and how to log its traffic.

function init() {
    console.log("🌐 Built-in Server Logger Active");

    // Start a simple management/UI server on port 11081
    const app = http.createServer();

    app.use((req, res, next) => {
        console.log(`[Server] 📨 Inbound Internal Request: ${req.method} ${req.url}`);
        next();
    });

    app.get("/", (req, res) => {
        res.status(200).json({
            status: "running",
            engine: "NetKit-Go",
            features: ["SOCKS5", "HTTP-MITM", "Tunnel", "AdBlock"]
        });
    });

    app.listen(11081);
    console.log("📡 Internal Management Server: http://localhost:11081");
}

/**
 * onConnect - Logs when someone connects to our internal servers as well
 */
function onConnect(conn) {
    // Port 11081 is our management server
    if (conn.dest.includes(":11081")) {
        console.log(`[Server] 🔌 Management Connection from ${conn.ip} (${conn.through})`);
    }
}

function closing() {
    console.log("Shutting down Server Logger.");
}
