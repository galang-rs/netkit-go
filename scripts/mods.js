// scripts/mods.js
// Modularized NetKit Engine Script

const { loadConfig, loadModLogs, loadJsonFile, config, rawDataMods } = require('./mods/config.js');
const { runTasks } = require('./mods/tasks.js');
const security = require('./mods/security.js');
const state = require('./mods/state.js');

function init() {
    loadConfig();
    const cfg = config();

    // Initialize Security Scope and Firewall
    if (typeof Security !== 'undefined') {
        Security.Scope.SetRole("Server");
        Security.Scope.SetScope(2, 0, "Global Access"); // 2 = ScopeAll

        if (cfg.app?.port) {
            Security.Firewall.AddRule({
                name: "Allow-Web-Port",
                priority: 1,
                action: "ALLOW",
                direction: "BOTH",
                dstPort: cfg.app.port,
                protocol: "tcp"
            });
        }
    }

    state.modLogs = loadModLogs();

    // Run tasks immediately on startup
    runTasks();

    // Schedule tasks
    if (cfg.app?.interval?.slotDurationMs) {
        setInterval(runTasks, cfg.app.interval.slotDurationMs);
    }

    // Create NetKit HTTP Server
    const app = http.createServer();


    const getQuery = (url) => {
        if (!url) return {};
        try {
            const query = {};
            const parts = url.split('?');
            if (parts.length > 1) {
                parts[1].split('&').forEach(item => {
                    const [k, v] = item.split('=');
                    if (k) query[k] = decodeURIComponent(v || "");
                });
            }
            return query;
        } catch (e) { return {}; }
    };

    // Helper to generate the unified data object
    const getFormattedData = () => {
        const mods = [...(state.modsCache?.mods ?? [])]
            .map(m => ({
                name: m?.name ?? "unknown",
                updated: (m?.updated ?? 0) * 1000, // Convert to ms for web
                undercover: (m?.undercover === "iya" || m?.undercover === true),
                idle: (m?.idle === "iya" || m?.idle === true),
                role: rawDataMods()[m?.name.toLowerCase()] ?? 3
            }));

        return {
            count_player: state.countPlayer || 0,
            mods: mods,
            last_updated: state.lastUpdate,
            last_updated_ms: state.lastUpdateTime ? state.lastUpdateTime.getTime() : 0,
            ban_rate: state.banRate || 0,
            server_maintance: state.serverMaintance || false,
            nuke_world: state.nukeWorld || 0,
            ban_player: state.banPlayer || 0
        };
    };

    // Root route
    app.get("/", (req, res) => {
        const uptimeSeconds = Math.floor((Date.now() - (state.startTime || Date.now())) / 1000);
        res.json({
            status: "running",
            uptime: uptimeSeconds,
            total_request: state.cumulativeRequestCount || 0,
            request_per_minute: state.globalRequestCount || 0
        });
    });

    // Unified mods route
    app.get("/mods", (req, res) => {
        const query = getQuery(req.url);
        const formatFlag = query.table;
        const data = getFormattedData();

        if (formatFlag === "lua") {
            const luaTable = `
return {
    count_player = ${data.count_player},
mods = {
    ${(data.mods ?? []).map(m =>
                `        { name = "${m.name}", updated = ${m.updated}, undercover = ${m.undercover}, idle = ${m.idle}, role = ${m.role} }`
            ).join(",\n")
                }
    },
last_updated = "${data.last_updated}",
    server_maintance = ${data.server_maintance},
ban_rate = ${data.ban_rate},
nuke_world = ${data.nuke_world},
ban_player = ${data.ban_player}
}`.trim();

            res.setHeader('Content-Type', 'text/plain');
            return res.send(luaTable);
        }

        // Default to JSON
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Cache-Control', 'no-cache');
        res.json(data);
    });

    app.get("/history", (req, res) => {
        const history = loadJsonFile("logPlayer.json", { historyPlayer: [] });
        res.json(history);
    });

    if (cfg.app?.port) {
        app.listen(cfg.app.port);
        console.log(`[JS] Server listening at http://localhost:${cfg.app.port}`);
    }
}
// ←[0m←[32m[JS] {"Dest":"localhost","IP":"::1","Through":"direct","RemoteAddr":"[::1]:49656","LocalAddr":"::1","LocalHost":"direct","Type":"js_http_server","Source":"[::1]:49656"}
function onConnect(info) {
    state.globalRequestCount++;
    state.cumulativeRequestCount++;
    // console.log(JSON.stringify(info))
    if (info.Type !== "js_http_server") {
        return;
    }
    if (info.Dest.toLowerCase() !== "gt.galang.blog" && info.Dest.toLowerCase() !== "localhost" && info.Dest.toLowerCase() !== "127.0.0.1") {
        info.Drop();
        return;
    }
    if (info.Path !== "/mods" && info.Path !== "/history" && info.Path !== "/") {
        info.Drop();
        return;
    }
    if (security.isGlobalBlocked()) {
        info.Drop();
        return;
    }

    const ip = info.IP || "unknown";
    if (ip === "::1" || ip === "127.0.0.1") return;

    const isAllowed = security.checkRateLimit(ip, "/main-api", 10, 60000, "onConnect");

    if (!isAllowed) {
        info.Drop();
        return;
    }
    // Proactive dropping for specific endpoint limits
    if (info.Path.includes("/mods") && !security.checkRateLimit(ip, "/mods", 5, 60000, "onConnect:/mods")) {
        info.Drop();
        return;
    }
    if (info.Path.includes("/history") && !security.checkRateLimit(ip, "/history", 5, 60000, "onConnect:/history")) {
        info.Drop();
        return;
    }
}

function onRequest(ctx) { }

function onError(err) {
    console.error("❌ ENGINE ERROR:", err);
}

setInterval(() => { state.globalRequestCount = 0; }, 60000);
