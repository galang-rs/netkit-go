// agent/google/main.js
// NetKit entry point — Web Search API Server (DuckDuckGo)
// Pure bootstrap: creates server, delegates routing to Router layer

const Router = require('./routes/router.js');

var stats = {
    requestCount: 0,
    successCount: 0,
    failureCount: 0,
    totalInputTokens: 0,
    totalOutputTokens: 0,
    startTime: Date.now()
};

function init() {
    console.log('[Search] 🔍 Initializing Web Search API (DuckDuckGo)...');
    const PORT = 8081;

    if (typeof Security !== 'undefined') {
        Security.Scope.SetRole("Server");
        Security.Scope.SetScope(2, 0, "Global Access");

        if (PORT) {
            Security.Firewall.AddRule({
                name: "Allow-Search-Web-Port",
                priority: 1,
                action: "ALLOW",
                direction: "BOTH",
                dstPort: PORT,
                protocol: "tcp"
            });
        }
    }

    var app = http.createServer();
    var router = new Router(stats);
    router.register(app);

    app.listen(PORT);
    console.log('[Search] ✅ API server listening on http://localhost:' + PORT);
    console.log('[Search] Endpoints:');
    console.log('  GET  /                       — Status');
    console.log('  GET  /v1/models              — List models');
    console.log('  POST /v1/chat/completions    — Web Search (OpenAI-compatible)');
}

function onConnect(info) {
    if (info.Type !== "js_http_server") return;
    if (info.Dest.toLowerCase() !== "localhost:8081" && info.Dest.toLowerCase() !== "127.0.0.1:8081") {
        info.Drop();
        return;
    }
    var allowed = Router.ALLOWED_PATHS;
    var found = false;
    for (var i = 0; i < allowed.length; i++) {
        if (info.Path === allowed[i]) { found = true; break; }
    }
    if (!found) { info.Drop(); return; }
}

function onError(err) {
    console.error('[Search] ❌ Engine error:', err);
}
