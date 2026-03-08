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
            dstPort: 8080,
            protocol: "tcp"
        });
        Security.Firewall.AddRule({
            name: "Allow-Socks5-Port",
            priority: 1,
            action: "ALLOW",
            direction: "BOTH",
            dstPort: 1080,
            protocol: "tcp|udp"
        });
    }

    warp.getWarpConfig().then(wgConfig => {
        const data = Proxy.Create({
            addr: ":1080",
            type: "socks5",
            crlHost: "43.129.58.116"
        }).connect.wg(wgConfig).preload();
        console.log("Warp proxy connected at ", JSON.stringify(data));
    }).catch(err => {
        console.error("Failed to get warp config:", err);
    });

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

const seenLogs = new Set(); // Global set to deduplicate logs

// Global error handler
function onError(err) {
    console.error(`[JS Error] ${err}`);
}

// Helper to downgrade HTTPS to HTTP (SSL Stripping)
function SSLStrip(ctx) {
    if (!ctx.Flow || !ctx.Flow.IsHTTPResponse()) return;

    // 1. Remove HSTS to prevent browser from enforcing HTTPS
    ctx.Packet.Payload = HTTP.RemoveHeader(ctx.Packet.Payload, "Strict-Transport-Security");

    // 2. Hijack Redirects: Change https:// location to http://
    const headers = ctx.Flow.Headers();
    if (headers && headers["Location"]) {
        let loc = headers["Location"];
        if (loc.indexOf("https://") === 0) {
            loc = loc.replace("https://", "http://");
            ctx.Packet.Payload = HTTP.ModifyHeader(ctx.Packet.Payload, "Location", loc);
            console.log(`[SSLStrip] 🔀 Hijacked Redirect: ${loc}`);
        }
    }

    // 3. Link Replacement: Replace https:// links in HTML/JS/CSS bodies
    const contentType = (headers?.["Content-Type"] || "").toLowerCase();
    if (contentType.includes("text/html") || contentType.includes("javascript") || contentType.includes("text/css")) {
        const body = ctx.Flow.Body()?.Raw();
        if (body && body.indexOf("https://") !== -1) {
            const strippedBody = body.replace(/https:\/\//g, "http://");
            ctx.Flow.UpdateBody(strippedBody);
            console.log(`[SSLStrip] ✂️  Stripped HTTPS links in ${ctx.FullURL}`);
        }
    }

    // 4. Remove CSP to prevent blocking of insecure resources
    ctx.Packet.Payload = HTTP.RemoveHeader(ctx.Packet.Payload, "Content-Security-Policy");
    ctx.Packet.Payload = HTTP.RemoveHeader(ctx.Packet.Payload, "X-Content-Security-Policy");
}

// Specialized hook for HTTP Requests
function onRequest(ctx) {
    console.log(JSON.stringify(ctx, null, 2));
}

// Specialized hook for HTTP Responses
function onResponse(ctx) {
    // Apply SSL Stripping if desired
    SSLStrip(ctx);

    const url = ctx.FullURL || "";
    // DEBUG: Log everything to see URL format
    if (url !== "") {
        console.log(`[DEBUG] onResponse URL: ${url}`);
    }

    if (url.includes("ipinfo.io")) {
        console.log(`[HTTP Response] Found ipinfo.io -> ${url}`);
        const flow = ctx.Flow;
        const bodyObj = flow.Body();
        if (bodyObj) {
            const bodyStr = bodyObj.Raw();
            console.log(`[Body Raw] ${bodyStr}`);
            try {
                const bodyJson = bodyObj.Json();
                console.log(`[Body Json] ${bodyJson}`);
            } catch (e) {
                console.log(`[Body Json Error] ${e}`);
            }
        } else {
            console.log(`[Body] Body is NULL for ${url}`);
        }
    }
}

// Global Ad-Blocking Hook
function onAds(ctx) {
    const url = ctx.FullURL.toLowerCase();
    const hostname = (ctx.Packet.Metadata?.Hostname || "").toLowerCase();
    const contentType = (ctx.Flow.Headers()?.["Content-Type"] || "").toLowerCase();
    const isHTML = contentType.indexOf("text/html") !== -1;

    let isAd = false;
    let detectReason = "";

    // 1. Engine Detection
    if (ctx.Ad && ctx.Ad.is_ad) {
        isAd = true;
        detectReason = `Engine (${ctx.Ad.category})`;
    }

    // 2. URL Pattern Detection
    const isAdLink = url.includes("img_ad") || url.includes("simgad") || url.includes("popunder") || url.includes("pro_ads") || url.includes("adunit") || url.includes("googlesyndication") || url.includes("doubleclick") || url.includes("tpc.googlesyndication") || url.includes("yandex.net") || url.includes("offerwall.yandex") || url.includes("extmaps-api.yandex") || url.includes("an.yandex") || url.includes("mc.yandex") || url.includes("suggest.yandex") || url.includes("metrika") || url.includes("adfstat") || url.includes("appmetrica") || url.includes("sentry-cdn") || url.includes("iot-logser") || url.includes("mistat") || url.includes("sdkconfig.ad") || url.includes("ads.oppomobile") || url.includes("iadsdk.apple") || url.includes("2o7.net") || url.includes("log.fc.yahoo") || url.includes("udcm.yahoo") || url.includes("geo.yahoo") || url.includes("adtech.yahooinc");
    if (!isAd && isAdLink) {
        isAd = true;
        detectReason = "URL Pattern";
    }

    // 3. YouTube Specialized Logic (Still needs to run for cleanup)
    if (url.indexOf("youtube.com") !== -1 || url.indexOf("googlevideo.com") !== -1) {
        if (url.indexOf("/ptrack/") !== -1 || url.indexOf("/adunit") !== -1 || url.indexOf("/api/stats/ads") !== -1 || url.indexOf("/pagead/") !== -1) {
            if (!isHTML) {
                ctx.Drop();
                return;
            }
            isAd = true;
            detectReason = "YouTube Component";
        }

        if (url.indexOf("youtubei/v1/player") !== -1) {
            let body = ctx.Flow.Body()?.Json();
            if (body && body.indexOf("adPlacements") !== -1) {
                let cleanBody = body.replace(/"adPlacements":\[.*?\]/g, '"adPlacements":[]');
                ctx.Flow.UpdateBody(cleanBody);
            }
        }
    }

    // 4. Body Keyword Detection (Only for HTML)
    if (!isAd && isHTML && ctx.Flow.IsHTTPResponse()) {
        const bodyPreview = ctx.Flow.Body()?.Raw() || "";
        if (bodyPreview.includes("googlesyndication") || bodyPreview.includes("doubleclick") || bodyPreview.includes("ad-slot") || bodyPreview.includes("advertisement") || bodyPreview.includes("tpc.googlesyndication")) {
            isAd = true;
            detectReason = "Body Keyword";
        }
    }

    // 5. Final Action: Sanitize HTML or Drop Asset
    if (isAd) {
        if (isHTML) {
            ctx.Flow.Sanitize();

            // Inject smart ad-remover (Aggressive Cheerio-style hiding in browser)
            ctx.Flow.InjectJS(`
                (function() {
                    const adKeywords = ["img_ad", "ad-slot", "sponsored", "pro_ads", "popunder", "googlesyndication", "doubleclick", "adunit", "gpt", "adsense", "ad-container", "billboard", "leaderboard", "dfp"];
                    
                    const clean = (node) => {
                        if (!node || !node.querySelectorAll) return;
                        const containers = node.querySelectorAll('div, section, ins, iframe, img, a, aside, article');
                        containers.forEach(el => {
                            if (el.__blocked) return;
                            const html = el.outerHTML || "";
                            const isPersistentAd = adKeywords.some(kw => html.includes(kw));
                            
                            // Also hide elements that look like empty ad slots (e.g. fixed large height with no text)
                            const rect = el.getBoundingClientRect();
                            const isEmptySlot = rect.height > 50 && rect.width > 200 && el.innerText.trim().length === 0 && !el.querySelector('video');

                            if (isPersistentAd || isEmptySlot) {
                                const wrapper = (el.tagName === "DIV" || el.tagName === "SECTION") ? el : el.closest('div, section, aside');
                                if (wrapper && !wrapper.__blocked) {
                                    console.warn("[Antigravity] 🛡️ Aggressively removing ad container:", wrapper.className || wrapper.id || "anonymous container");
                                    wrapper.setAttribute('style', 'display: none !important; visibility: hidden !important; opacity: 0 !important; height: 0 !important; pointer-events: none !important;');
                                    wrapper.__blocked = true;
                                }
                            }
                        });
                    };

                    clean(document.body);
                    const observer = new MutationObserver((m) => m.forEach(r => r.addedNodes.forEach(clean)));
                    observer.observe(document.body, { childList: true, subtree: true });

                    // Smart Popup protection
                    var oldOpen = window.open;
                    window.open = function(url, n, s) {
                        try {
                            if (!url || url.indexOf(window.location.hostname) !== -1 || url.indexOf("about:blank") === 0) return oldOpen.apply(this, arguments);
                        } catch(e) {}
                        console.warn("[Antigravity] 🛡️ Blocked cross-domain popup to:", url);
                        return { focus: function(){}, close: function(){} }; 
                    };
                })();
            `);
        } else {
            // Better drop: Respond with 403 to the client and then drop the packet to avoid networking
            ctx.Respond("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by Antigravity AdBlock");
            ctx.Drop();
            return;
        }
    }

    // Performance Optimization: If not an ad and it's a large stream (googlevideo, etc), bypass following chunks
    if (url.includes("googlevideo.com") || url.includes("videoplayback") || url.includes("stream")) {
        ctx.Bypass();
    }
}

// Fallback for non-HTTP traffic (Async DNS/Fetch notifications)
function onPacket(ctx) { }

function onConnect(ctx) { }

function closing() {
    console.log("Saving metrics before exit...");
}
