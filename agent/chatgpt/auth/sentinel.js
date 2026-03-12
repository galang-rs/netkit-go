// scripts/chatgpt/auth/sentinel.js
// Sentinel authentication flow for ChatGPT anonymous access
// Steps: fetch homepage (with initial snapshot) → prepare → solve PoW → finalize

const Helpers = require('../core/helpers.js');
const Encoding = require('../core/encoding.js');
const Fingerprint = require('../config/fingerprint.js');
const Headers = require('../network/headers.js');
const ProofOfWork = require('./pow.js');

class Sentinel {
    /**
     * Perform the full sentinel authentication flow.
     * Uses the initial snapshot from WARP registration for TLS fingerprint continuity.
     *
     * @param {string} proxyUrl  — WARP SOCKS5 proxy URL
     * @param {object} snapshot  — Initial fingerprint.snapshoot() from WARP registration
     * @returns {{ fp, config, deviceId, oaiBuildId, token, powAnswer, gptHomepage }}
     */
    static async authenticate(proxyUrl, snapshot) {
        // ── Step 1: Fetch homepage using snapshot from WARP init ──
        console.log('[Auth] Fetching homepage via WARP (using WARP snapshot)...');
        var homepageResp = await fetch('https://chatgpt.com/translate', {
            method: 'GET',
            fingerprint: snapshot,
            agent: proxyUrl,
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9'
            }
        });

        if (!homepageResp.ok) {
            throw new Error('Failed to fetch ChatGPT homepage: HTTP ' + homepageResp.status + ' — ' + (homepageResp.body || '').substring(0, 200));
        }

        var fp = homepageResp.fingerprint.snapshoot();
        console.log('[Auth] TLS fingerprint updated from homepage');

        var gptHomepage = homepageResp.body || '';

        // Extract build IDs
        var seqMatch = gptHomepage.match(/data-seq="([^"]+)"/);
        var oaiBuildId = seqMatch ? seqMatch[1] : null;

        // Generate config — pass snapshot for default overrides (UA, screen, heap, version)
        var config = Fingerprint.getConfig(gptHomepage, fp);
        var deviceId = Helpers.generateUUID();

        // ── Step 2: Sentinel prepare ──
        console.log('[Auth] Preparing sentinel challenge...');
        var prepareBody = JSON.stringify({ p: 'gAAAAAC' + Encoding.m1(config) });

        var req1 = await fetch('https://chatgpt.com/backend-anon/sentinel/chat-requirements/prepare', {
            method: 'POST',
            fingerprint: fp,
            agent: proxyUrl,
            headers: Headers.build(config, deviceId, oaiBuildId),
            body: prepareBody
        });

        if (!req1.ok) {
            throw new Error('Sentinel prepare failed: HTTP ' + req1.status + ' — ' + (req1.body || '').substring(0, 200));
        }
        fp = req1.fingerprint.snapshoot();
        var res1 = JSON.parse(req1.body);

        // ── Step 3: Solve proof-of-work ──
        console.log('[Auth] Solving proof-of-work...');
        console.time('pow');
        var powAnswer = ProofOfWork.getAnswer(res1);
        console.timeEnd('pow');

        // ── Step 4: Sentinel finalize ──
        console.log('[Auth] Finalizing sentinel...');
        var finalizeBody = JSON.stringify({
            prepare_token: res1.prepare_token,
            proofofwork: powAnswer
        });

        var req2 = await fetch('https://chatgpt.com/backend-anon/sentinel/chat-requirements/finalize', {
            method: 'POST',
            fingerprint: fp,
            agent: proxyUrl,
            headers: Headers.build(config, deviceId, oaiBuildId),
            body: finalizeBody
        });

        if (!req2.ok) {
            throw new Error('Sentinel finalize failed: HTTP ' + req2.status + ' — ' + (req2.body || '').substring(0, 200));
        }
        fp = req2.fingerprint.snapshoot();
        var res2 = JSON.parse(req2.body);

        return {
            fp: fp,
            config: config,
            deviceId: deviceId,
            oaiBuildId: oaiBuildId,
            token: res2.token,
            powAnswer: powAnswer,
            gptHomepage: gptHomepage
        };
    }
}

module.exports = Sentinel;
