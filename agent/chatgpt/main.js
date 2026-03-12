// scripts/chatgpt/main.js
// NetKit entry point — ChatGPT Free API Server
// Pure bootstrap: creates server, delegates routing to Router layer

const Router = require('./routes/router.js');

// ── Shared stats (passed by reference to Router) ──
var stats = {
    requestCount: 0,
    successCount: 0,
    failureCount: 0,
    totalInputTokens: 0,
    totalOutputTokens: 0,
    startTime: Date.now()
};

function init() {
    console.log('[ChatGPT] 🚀 Initializing ChatGPT Free API...');
    const PORT = 8080;

    // ── Security setup ──
    if (typeof Security !== 'undefined') {
        Security.Scope.SetRole("Server");
        Security.Scope.SetScope(2, 0, "Global Access"); // 2 = ScopeAll

        if (PORT) {
            Security.Firewall.AddRule({
                name: "Allow-Web-Port",
                priority: 1,
                action: "ALLOW",
                direction: "BOTH",
                dstPort: PORT,
                protocol: "tcp"
            });
        }
    }

    // ── Create server & register routes ──
    var app = http.createServer();
    var router = new Router(stats);
    router.register(app);

    // ── Start listening ──
    app.listen(PORT);
    console.log('[ChatGPT] \u2705 API server listening on http://localhost:' + PORT);
    console.log('[ChatGPT] Endpoints:');
    console.log('  GET  /                       \u2014 Status');
    console.log('  GET  /v1/models              \u2014 List models');
    console.log('  POST /v1/chat/completions    \u2014 OpenAI-compatible chat');
    console.log('  POST /v1/images/analyze      \u2014 Image analysis (URL/base64/hex)');
}

function onConnect(info) {
    if (info.Type !== "js_http_server") {
        return;
    }
    if (info.Dest.toLowerCase() !== "43.129.58.116:8080" && info.Dest.toLowerCase() !== "localhost:8080" && info.Dest.toLowerCase() !== "127.0.0.1:8080") {
        info.Drop();
        return;
    }
    // Use Router's allowed paths list
    var allowed = Router.ALLOWED_PATHS;
    var found = false;
    for (var i = 0; i < allowed.length; i++) {
        if (info.Path === allowed[i]) {
            found = true;
            break;
        }
    }
    if (!found) {
        info.Drop();
        return;
    }
}

function onError(err) {
    console.error('[ChatGPT] ❌ Engine error:', err);
}
