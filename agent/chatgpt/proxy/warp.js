// scripts/chatgpt/proxy/warp.js
// WARP proxy rotation — each request gets a fresh registration = different IP
// Also captures initial fingerprint.snapshoot() from the registration fetch

class Warp {
    /**
     * Register a new Cloudflare WARP account with a fresh keypair.
     * Also captures the TLS fingerprint snapshot from the response.
     *
     * @returns {{ data: object, snapshot: object }} — registration data + initial fingerprint snapshot
     */
    static async register(pubKey) {
        var payload = JSON.stringify({
            install_id: "",
            tos: new Date().toISOString(),
            key: pubKey,
            fcm_token: "",
            type: "Android",
            locale: "en_US"
        });

        var resp = await fetch('https://api.cloudflareclient.com/v0a2485/reg', {
            method: 'POST',
            headers: {
                'User-Agent': 'okhttp/3.12.1',
                'Content-Type': 'application/json; charset=UTF-8'
            },
            body: payload,
            profile: 'chrome'
        });

        if (!resp.ok) {
            throw new Error('WARP register failed: ' + resp.status + ' - ' + (resp.body || '').substring(0, 200));
        }

        // Capture initial TLS fingerprint snapshot
        var snapshot = resp.fingerprint.snapshoot();
        console.log('[Warp] ✅ Initial fingerprint snapshot captured');

        return {
            data: JSON.parse(resp.body),
            snapshot: snapshot
        };
    }

    /**
     * Generate a fresh WireGuard config for Cloudflare WARP.
     * @returns {{ wgConfig: string, snapshot: object }} — WireGuard config + initial snapshot
     */
    static async generateConfig() {
        console.log('[Warp] Generating fresh X25519 keys...');
        var keys = Crypto.GenerateX25519();

        console.log('[Warp] Registering new WARP account...');
        var result = await Warp.register(keys.publicKey);
        var reg = result.data;

        if (!reg.config || !reg.config.peers || reg.config.peers.length === 0) {
            throw new Error('Invalid WARP registration: No peers found');
        }

        var peer = reg.config.peers[0];
        var interfaceAddr = reg.config.interface.addresses;
        var endpoint = (peer.endpoint && (peer.endpoint.v4 || peer.endpoint.host)) || '162.159.192.1:2408';

        var wgConfig = [
            '[Interface]',
            'PrivateKey = ' + keys.privateKey,
            'Address = ' + (interfaceAddr.v4 || '172.16.0.2/32') + ', ' + (interfaceAddr.v6 || 'fd01:5ca1:ab1e:8273:c81::c/128'),
            'DNS = 1.1.1.1, 1.0.0.1',
            'MTU = 1280',
            '',
            '[Peer]',
            'PublicKey = ' + peer.public_key,
            'Endpoint = ' + endpoint,
            'AllowedIPs = 0.0.0.0/0, ::/0',
            'PersistentKeepalive = 25'
        ].join('\n');

        return { wgConfig: wgConfig, snapshot: result.snapshot };
    }

    /**
     * Create a temporary WARP SOCKS5 proxy with a fresh config (new IP).
     * @returns {{ proxyUrl: string, proxyObj: object, snapshot: object }}
     */
    static async createProxy() {
        var generated = await Warp.generateConfig();
        var maxRetries = 5;
        var proxyObj = null;
        var proxyUrl = null;

        for (var i = 0; i < maxRetries; i++) {
            try {
                var port = Math.floor(Math.random() * (40000 - 10000 + 1)) + 10000;
                var addr = '127.0.0.1:' + port;

                proxyObj = Proxy.Create({ addr: addr, type: 'socks5' });
                proxyObj.connect.wg(generated.wgConfig);

                proxyUrl = 'socks5://' + addr;
                console.log('[Warp] ✅ Created proxy: ' + proxyUrl + ' (ID: ' + proxyObj.id + ')');
                break;
            } catch (bindErr) {
                console.warn('[Warp] Bind retry ' + (i + 1) + ': ' + bindErr.message);
                proxyObj = null;
            }
        }

        if (!proxyObj) {
            throw new Error('Failed to bind WARP proxy after ' + maxRetries + ' attempts');
        }

        return { proxyUrl: proxyUrl, proxyObj: proxyObj, snapshot: generated.snapshot };
    }

    /**
     * Drop a previously created WARP proxy.
     */
    static dropProxy(proxyObj) {
        if (proxyObj && proxyObj.id) {
            try {
                Proxy.Drop(proxyObj.id);
                console.log('[Warp] Dropped proxy: ' + proxyObj.id);
            } catch (e) {
                // Ignore
            }
        }
    }

    /**
     * Execute a callback with a temporary WARP proxy (fresh IP).
     * Callback receives BOTH proxyUrl AND the initial fingerprint snapshot.
     * Proxy is automatically dropped after the callback finishes.
     *
     * @param {function(string, object): *} callback — (proxyUrl, snapshot) => result
     */
    static async withProxy(callback) {
        var warp = null;
        try {
            warp = await Warp.createProxy();
            return await callback(warp.proxyUrl, warp.snapshot);
        } finally {
            if (warp) Warp.dropProxy(warp.proxyObj);
        }
    }
}

module.exports = Warp;
