/**
 * Native NetKit-Go Provider for Surfshark
 * No Node.js dependencies.
 */

async function nativeRequest(url, options = {}) {
    if (!options.profile) options.profile = "android";

    console.log(`[nativeRequest] Fetching ${url}...`);
    const resp = await fetch(url, options);
    console.log(`[nativeRequest] Response: ${resp.status} ${resp.ok}`);

    // Capture fingerprint if snapshoot is available for engine-level consistency
    if (resp.fingerprint && resp.fingerprint.snapshoot) {
        options.fingerprint = resp.fingerprint.snapshoot();
    }

    const body = resp.body || "";
    if (!resp.ok) {
        throw new Error(`Surfshark API Error: ${resp.status} - ${body.substring(0, 200)}`);
    }

    try {
        console.log(`[nativeRequest] Parsing JSON (body length: ${body.length})...`);
        const parsed = JSON.parse(body);
        console.log(`[nativeRequest] JSON Parse Success.`);
        return parsed;
    } catch (e) {
        console.error(`[nativeRequest] JSON Parse Error for ${url}. Body starts with: ${body.substring(0, 500)}`);
        throw new Error(`Failed to parse JSON response from ${url}`);
    }
}

async function getSurfsharkToken(username, password) {
    const payload = JSON.stringify({ username, password });
    const standardHeaders = {
        'Content-Type': 'application/json',
        'X-App-Client-Name': 'surfshark-windows-app',
        'User-Agent': 'okhttp/3.12.1',
        'Accept': 'application/json'
    };

    const options = {
        method: 'POST',
        headers: standardHeaders,
        body: payload,
        profile: "android"
    };

    try {
        console.log(`[Surfshark] Attempting login at v1/client/auth/login...`);
        const res = await nativeRequest('https://api.surfshark.com/v1/client/auth/login', options);
        if (res.token) {
            console.log(`[Surfshark] Token obtained successfully via client/auth.`);
            return res.token;
        }
    } catch (e) {
        console.warn(`[Surfshark] Client login failed: ${e.message}`);
    }

    try {
        console.log(`[Surfshark] Falling back to v1/auth/login...`);
        // For fallback, sometimes the API requires a clean header set or different Client Name
        options.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'okhttp/3.12.1'
        };
        const res = await nativeRequest('https://api.surfshark.com/v1/auth/login', options);
        if (res.token) {
            console.log(`[Surfshark] Token obtained successfully via auth/login.`);
            return res.token;
        }
    } catch (e) {
        console.error(`[Surfshark] All login attempts failed. Please check your credentials.`);
        throw new Error(`Surfshark Auth Failed: ${e.message}`);
    }
}

async function getSurfsharkServers() {
    console.log(`[Surfshark] Fetching clusters...`);
    return await nativeRequest('https://api.surfshark.com/v4/server/clusters/generic', {
        method: 'GET',
        headers: {
            'Accept': 'application/json',
            'User-Agent': 'okhttp/3.12.1'
        },
        profile: "android"
    });
}

async function registerSurfsharkKey(token, pubKey) {
    const payload = JSON.stringify({ pubKey });
    const options = {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'X-App-Client-Name': 'surfshark-windows-app',
            'User-Agent': 'okhttp/3.12.1'
        },
        body: payload,
        profile: "android"
    };
    try {
        console.log(`[Surfshark] Registering key...`);
        const res = await nativeRequest('https://api.surfshark.com/v1/account/v1/config/wireguard/keys', options);
        return res.address;
    } catch (e) {
        console.log(`[Surfshark] Key registration fallback: ${e.message}`);
        const keys = await nativeRequest('https://api.surfshark.com/v1/account/v1/config/wireguard/keys', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'User-Agent': 'okhttp/3.12.1'
            },
            profile: "android"
        });
        const match = keys.find(k => k.pubKey === pubKey);
        if (match) return match.address;
        throw e;
    }
}

async function getSurfsharkWGConfig(username, password, regionOrServer, staticPriv, staticPub) {
    try {
        let server = regionOrServer;
        if (typeof regionOrServer === 'string') {
            console.log(`[Surfshark] getSurfsharkWGConfig started for region: ${regionOrServer}`);
            const servers = await getSurfsharkServers();
            server = servers.find(s =>
                (s.country && s.country.toLowerCase() === regionOrServer.toLowerCase()) ||
                (s.location && s.location.toLowerCase() === regionOrServer.toLowerCase()) ||
                (s.countryCode && s.countryCode.toLowerCase() === regionOrServer.toLowerCase())
            );
        } else {
            console.log(`[Surfshark] getSurfsharkWGConfig using provided server object: ${server.location || server.countryCode}`);
        }

        if (!server) throw new Error(`Region ${regionOrServer} not found or invalid server object`);

        let priv, pub, address;

        if (staticPriv && staticPub) {
            console.log(`[Surfshark] Using static keys...`);
            priv = staticPriv;
            pub = staticPub;
            address = "10.14.0.2/16"; // Default internal IP for static keys
        } else {
            const token = await getSurfsharkToken(username, password);
            if (!token) throw new Error("Failed to obtain Surfshark token");

            console.log(`[Surfshark] Generating keys...`);
            const keys = Crypto.GenerateX25519();
            priv = keys.privateKey;
            pub = keys.publicKey;
            address = await registerSurfsharkKey(token, pub);
        }

        console.log(`[Surfshark] Building config for ${server.hostname || server.connectionName}...`);
        const config = [
            `[Interface]`,
            `PrivateKey = ${priv}`,
            `Address = ${address}`,
            `DNS = 162.252.172.57, 149.154.159.92`,
            `MTU = 1280`,
            ``,
            `[Peer]`,
            `PublicKey = ${server.pubKey}`,
            `Endpoint = ${server.hostname || server.connectionName}:51820`,
            `AllowedIPs = 0.0.0.0/0`,
            `PersistentKeepalive = 25`
        ].join('\n');

        return config;
    } catch (e) {
        console.error(`[Surfshark ERROR] ${e.message}`);
        throw e;
    }
}

/**
 * Executes a callback with a temporary Surfshark proxy.
 * The proxy is created before the callback and destroyed immediately after.
 */
async function withSurfshark(username, password, regionOrServer, callback) {
    let proxyObj = null;
    let proxyUrl = null;
    const maxRetries = 5;

    try {
        const wgConfig = await getSurfsharkWGConfig(username, password, regionOrServer, null, null);

        // Try to bind to a random port with retries
        for (let i = 0; i < maxRetries; i++) {
            try {
                const port = Math.floor(Math.random() * (40000 - 10000 + 1)) + 10000;
                const addr = `127.0.0.1:${port}`;

                proxyObj = Proxy.Create({ addr: addr, type: "socks5" });
                proxyObj.connect.wg(wgConfig);

                proxyUrl = `socks5://${addr}`;
                console.log(`[Surfshark] Created temporary proxy for request: ${proxyUrl} (ID: ${proxyObj.id})`);
                break; // Bind successful
            } catch (bindErr) {
                console.warn(`[Surfshark Warning] Failed to bind to random port: ${bindErr.message}. Retrying...`);
                proxyObj = null;
            }
        }

        if (!proxyObj) {
            throw new Error(`Failed to bind Surfshark proxy after ${maxRetries} attempts.`);
        }

        return await callback(proxyUrl);
    } catch (e) {
        console.error(`[Surfshark ERROR] ${e.message}`);
        throw e;
    } finally {
        if (proxyObj && proxyObj.id) {
            console.log(`[Surfshark] Dropping temporary proxy: ${proxyObj.id}`);
            try {
                Proxy.Drop(proxyObj.id);
            } catch (err) {
                // Ignore drop err
            }
        }
    }
}

module.exports = {
    getSurfsharkWGConfig: getSurfsharkWGConfig,
    getSurfsharkServers: getSurfsharkServers,
    getSurfsharkToken: getSurfsharkToken,
    registerSurfsharkKey: registerSurfsharkKey,
    withSurfshark: withSurfshark
};