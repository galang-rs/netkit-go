/**
 * Native NetKit-Go Provider for Cloudflare WARP
 * No Node.js dependencies.
 */

/**
 * Registers a new Cloudflare WARP account.
 */
async function registerWarp(pubKey, proxyURL = null) {
    const payload = JSON.stringify({
        install_id: "",
        tos: new Date().toISOString(),
        key: pubKey,
        fcm_token: "",
        type: "Android",
        locale: "en_US"
    });

    const options = {
        method: 'POST',
        headers: {
            'User-Agent': 'okhttp/3.12.1',
            'Content-Type': 'application/json; charset=UTF-8'
        },
        body: payload,
        profile: "chrome" // Use browser profile for safety
    };

    if (proxyURL) {
        options.proxy = proxyURL;
        console.log(`[WarpProvider] Registering via proxy: ${proxyURL}`);
    }

    console.log(`[WarpProvider] Registering public key: ${pubKey}`);
    const resp = await fetch('https://api.cloudflareclient.com/v0a2485/reg', options);
    console.log(`[WarpProvider] API Response: ${resp.status} ${resp.ok}`);

    // Capture fingerprint for engine-level consistency
    if (resp.fingerprint && resp.fingerprint.snapshoot) {
        options.fingerprint = resp.fingerprint.snapshoot();
    }

    if (!resp.ok) {
        throw new Error(`Cloudflare API Error: ${resp.status} - ${resp.body.substring(0, 200)}`);
    }

    try {
        return JSON.parse(resp.body);
    } catch (e) {
        console.error(`[WarpProvider] JSON Parse Error. Body starts with: ${resp.body.substring(0, 500)}`);
        throw new Error("Failed to parse Cloudflare WARP registration response");
    }
}

/**
 * Generates a WireGuard configuration string for Cloudflare WARP.
 */
async function getWarpConfig(proxyURL = null) {
    try {
        let keys, reg;
        const CACHE_FILE = "warp_cache.json";

        // 1. Try to load from cache
        if (FS.Exists(CACHE_FILE)) {
            try {
                const cachedData = FS.ReadString(CACHE_FILE);
                const cache = JSON.parse(cachedData);
                if (cache.keys && cache.reg && cache.reg.config && cache.reg.config.peers) {
                    console.log("[WarpProvider] Loaded WARP registration from cache.");
                    keys = cache.keys;
                    reg = cache.reg;
                }
            } catch (e) {
                console.log(`[WarpProvider] Failed to read cache: ${e.message}. Registering new...`);
            }
        }

        // 2. Register new if not cached
        if (!keys || !reg) {
            console.log("[WarpProvider] Generating native X25519 keys...");
            keys = Crypto.GenerateX25519();

            console.log("[WarpProvider] Registering with Cloudflare WARP...");
            reg = await registerWarp(keys.publicKey, proxyURL);

            try {
                // Save to cache for next run
                FS.SaveFileString(CACHE_FILE, JSON.stringify({ keys, reg }));
                console.log("[WarpProvider] Saved WARP registration to cache.");
            } catch (e) {
                console.log(`[WarpProvider] Failed to save cache: ${e.message}`);
            }
        }

        if (!reg.config || !reg.config.peers || reg.config.peers.length === 0) {
            throw new Error("Invalid registration response: No peers found");
        }

        const peer = reg.config.peers[0];
        const interfaceAddr = reg.config.interface.addresses;
        // Skip DNS resolution penalty by using a well-known WARP Anycast IP
        const endpoint = (peer.endpoint && (peer.endpoint.v4 || peer.endpoint.host)) || "162.159.192.1:2408";

        const config = [
            `[Interface]`,
            `PrivateKey = ${keys.privateKey}`,
            `Address = ${interfaceAddr.v4 || '172.16.0.2/32'}, ${interfaceAddr.v6 || 'fd01:5ca1:ab1e:8273:c81::c/128'}`,
            `DNS = 1.1.1.1, 1.0.0.1`,
            `MTU = 1280`,
            ``,
            `[Peer]`,
            `PublicKey = ${peer.public_key}`,
            `Endpoint = ${endpoint}`,
            `AllowedIPs = 0.0.0.0/0, ::/0`,
            `PersistentKeepalive = 25`
        ].join('\n');

        return config;
    } catch (e) {
        console.error(`[WarpProvider ERROR] ${e.message}`);
        throw e;
    }
}

/**
 * Executes a callback with a temporary WARP proxy.
 * The proxy is created before the callback and destroyed immediately after.
 */
async function withWarp(callback) {
    let proxyObj = null;
    let proxyUrl = null;
    const maxRetries = 5;

    try {
        const wgConfig = await getWarpConfig();

        // Try to bind to a random port with retries
        for (let i = 0; i < maxRetries; i++) {
            try {
                // Windows dynamic port range is usually 49152-65535, but we can hit reserved ones.
                // Let's use a safer range 10000-40000 to avoid Hyper-V reserved ports.
                const port = Math.floor(Math.random() * (40000 - 10000 + 1)) + 10000;
                const addr = `127.0.0.1:${port}`;

                proxyObj = Proxy.Create({ addr: addr, type: "socks5" });
                proxyObj.connect.wg(wgConfig);

                proxyUrl = `socks5://${addr}`;
                console.log(`[Warp] Created temporary proxy for request: ${proxyUrl} (ID: ${proxyObj.id})`);
                break; // Bind successful
            } catch (bindErr) {
                console.warn(`[Warp Warning] Failed to bind to random port: ${bindErr.message}. Retrying...`);
                proxyObj = null;
            }
        }

        if (!proxyObj) {
            throw new Error(`Failed to bind WARP proxy after ${maxRetries} attempts.`);
        }

        return await callback(proxyUrl);
    } catch (e) {
        console.error(`[Warp ERROR] ${e.message}`);
        throw e;
    } finally {
        if (proxyObj && proxyObj.id) {
            console.log(`[Warp] Dropping temporary proxy: ${proxyObj.id}`);
            try {
                Proxy.Drop(proxyObj.id);
            } catch (err) {
                // Ignore drop err
            }
        }
    }
}

module.exports = {
    getWarpConfig: getWarpConfig,
    withWarp: withWarp
};