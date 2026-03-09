const warp = require("./warp.js");

function init() {
    console.log("init() called");
    Domain("ipinfo.io"); // Enabled for body detection (ensure Root CA is trusted)

    // Initialize Security Scope and Firewall
    if (typeof Security !== 'undefined') {
        Security.Scope.SetRole("Server");
        Security.Scope.SetScope(2, 0, "Global Access"); // 2 = ScopeAll

        Security.Firewall.AddRule({
            name: "Allow-Web-Port",
            priority: 1,
            action: "ALLOW",
            direction: "BOTH",
            dstPort: 80, // Standard HTTP
            protocol: "tcp"
        });
        Security.Firewall.AddRule({
            name: "Allow-DNS",
            priority: 1,
            action: "ALLOW",
            direction: "BOTH",
            dstPort: 53,
            protocol: "udp"
        });
    }

    // Register domains for transparent interception
    Domain("*")

    const data = Proxy.Create({
        addr: ":1080",
        type: "socks5"
    })

    const app = http.createServer();

    app.get("/data", (req, res) => {
        res.status(200).json({
            message: FS.Data(),
            timestamp: new Date().toISOString()
        });
    });

    app.listen(8080);
    console.log("📡 Server listening on http://localhost:8080");
}
// Global error handler
function onError(err) {
    console.error(`[JS Error] ${err}`);
}

// Specialized hook for HTTP Requests
function onRequest(ctx) { }

// Specialized hook for HTTP Responses
function onResponse(ctx) { }


// Global Ad-Blocking Hook
function onAds(ctx) { }

// Fallback for non-HTTP traffic (Async DNS/Fetch notifications)
function onPacket(ctx) { }

function onConnect(ctx) {
    console.log(JSON.stringify(ctx, null, 2))
    return connect.proxy("socks5://samdues:geming@43.129.58.116:1080")
}

function closing() {
    console.log("Saving metrics before exit...");
}
