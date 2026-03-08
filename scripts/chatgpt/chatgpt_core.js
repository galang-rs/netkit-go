// chatgpt_core.js - Pure JS implementation of OpenAI Backend Anon Proxy

// Generate a random UUID
function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Generate random number string
function randomNumberString(length) {
    let result = '';
    const digits = '0123456789';
    for (let i = 0; i < length; i++) {
        result += digits.charAt(Math.floor(Math.random() * digits.length));
    }
    return result;
}

// FNV1a hash implementation
function fnv1aHash(input) {
    let hash = 2166136261;
    for (let i = 0; i < input.length; i++) {
        hash ^= input.charCodeAt(i);
        // Multiply by 16777619 using 32-bit math
        hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
        hash = hash >>> 0; // Convert to unsigned 32-bit uint
    }

    hash ^= hash >>> 16;
    hash = Math.imul(hash, 2246822507) >>> 0;
    hash ^= hash >>> 13;
    hash = Math.imul(hash, 3266489909) >>> 0;
    hash ^= hash >>> 16;

    let hex = hash.toString(16);
    while (hex.length < 8) hex = '0' + hex;
    return hex;
}

function solvePoW(seed, difficulty, config) {
    const maxIterations = 99999;
    const startTime = Date.now();

    for (let i = 0; i < maxIterations; i++) {
        let testConfig = Object.assign({}, config);
        testConfig.unknown1 = i;
        testConfig.performance_now = Date.now() - startTime;

        // Encode config (JSON -> Base64)
        let jsonStr = JSON.stringify(testConfig);
        let encoded = Crypto.Base64Encode(jsonStr);

        let hash = fnv1aHash(seed + encoded);

        if (hash.length >= difficulty.length && hash.substring(0, difficulty.length) <= difficulty) {
            return encoded + "~S"; // Success
        }
    }
    throw new Error("Failed to solve PoW");
}

const config = require("./config.js");

let persistentDeviceId = uuidv4();
let persistentFingerprint = null;
let persistentCookieJar = {};
let persistentConfig = null;

class ChatGPTClient {
    constructor() {
        this.deviceId = persistentDeviceId;
        this.buildId = "prod-" + randomNumberString(10);
        this.baseURL = "https://chatgpt.com";
        this.config = persistentConfig || config.get();
        persistentConfig = this.config;

        this.proxyUrl = config.get().proxyUrl;
        this.fingerprint = persistentFingerprint;
        this.cookieJar = persistentCookieJar;
    }

    async init() {
        let fetchOpts = {
            method: "GET",
            headers: { "User-Agent": this.userAgent, "Sec-Fetch-Mode": "cors" },
            profile: "chrome_120"
        };
        if (this.proxyUrl) { fetchOpts.agent = this.proxyUrl; }
        if (this.fingerprint) { fetchOpts.fingerprint = this.fingerprint; }

        try {
            console.log("[Core] Fetching latest build ID...");
            let resp = await fetch(this.baseURL + "/", fetchOpts);

            // Capture fingerprint for consistency
            if (resp.fingerprint && resp.fingerprint.snapshoot) {
                this.fingerprint = resp.fingerprint.snapshoot();
                persistentFingerprint = this.fingerprint;
            }
            console.log(JSON.stringify(this.fingerprint))

            let html = resp.body;
            this.updateCookies(resp.headers);

            let m = html.match(/data-build="([^"]+)"/);
            if (!m) m = html.match(/data-seq="([^"]+)"/);
            if (m) {
                this.buildId = m[1];
                this.config.build_id = this.buildId;
                console.log("[Core] Build ID found: " + this.buildId);
            }
        } catch (e) {
            console.log("[Core] Failed to fetch build ID, using fallback. " + e);
        }
    }

    updateCookies(headers) {
        if (!headers) return;
        let setCookie = headers["Set-Cookie"];
        if (!setCookie) return;

        let cookieArray = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (let cookieStr of cookieArray) {
            let parts = cookieStr.split(";")[0].split("=");
            if (parts.length >= 2) {
                let name = parts[0].trim();
                let value = parts.slice(1).join("=").trim();
                this.cookieJar[name] = value;
            }
        }
    }

    getCookieString() {
        let cookies = [];
        // Always include oai-did if not in jar
        if (!this.cookieJar["oai-did"]) {
            cookies.push("oai-did=" + this.deviceId);
        }
        for (let name in this.cookieJar) {
            cookies.push(name + "=" + this.cookieJar[name]);
        }
        return cookies.join("; ");
    }

    getHeaders() {

        return {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "Oai-Build-Id": this.buildId,
            "Oai-Client-Version": this.buildId,
            "Oai-DeviceId": this.deviceId,
            "Oai-Language": "en-US",
            "Origin": this.baseURL,
            "Referer": this.baseURL + "/",
            "Cookie": this.getCookieString(),
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Priority": "u=1, i"
        };
    }

    async prepare() {
        let configJson = JSON.stringify(this.config);
        let encodedConfig = Crypto.Base64Encode(configJson);

        let reqBody = { p: "gAAAAAC" + encodedConfig };

        let fetchOpts = {
            method: "POST",
            headers: this.getHeaders(),
            body: JSON.stringify(reqBody),
            profile: "chrome_120"
        };
        if (this.proxyUrl) { fetchOpts.agent = this.proxyUrl; }
        if (this.fingerprint) { fetchOpts.fingerprint = this.fingerprint; }

        let resp = await fetch(this.baseURL + "/backend-anon/sentinel/chat-requirements/prepare", fetchOpts);

        // Capture fingerprint and cookies
        if (resp.fingerprint && resp.fingerprint.snapshoot) {
            this.fingerprint = resp.fingerprint.snapshoot();
            persistentFingerprint = this.fingerprint;
        }
        this.updateCookies(resp.headers);

        if (resp.status !== 200) {
            throw new Error("Prepare failed: " + resp.body);
        }

        return JSON.parse(resp.body);
    }

    async finalize(challenge, powAnswer) {
        let reqBody = {
            prepare_token: challenge.prepare_token,
            proofofwork: powAnswer
        };

        let fetchOpts = {
            method: "POST",
            headers: this.getHeaders(),
            body: JSON.stringify(reqBody),
            profile: "chrome_120"
        };
        if (this.proxyUrl) { fetchOpts.agent = this.proxyUrl; }
        if (this.fingerprint) { fetchOpts.fingerprint = this.fingerprint; }

        let resp = await fetch(this.baseURL + "/backend-anon/sentinel/chat-requirements/finalize", fetchOpts);

        // Capture fingerprint and cookies
        if (resp.fingerprint && resp.fingerprint.snapshoot) {
            this.fingerprint = resp.fingerprint.snapshoot();
            persistentFingerprint = this.fingerprint;
        }
        this.updateCookies(resp.headers);

        if (resp.status !== 200) {
            throw new Error("Finalize failed: " + resp.body);
        }

        return JSON.parse(resp.body).token;
    }

    async generateToken() {
        let challenge = await this.prepare();
        let powAnswer = "";

        if (challenge.proofofwork && challenge.proofofwork.required) {
            console.log("[Core] Solving PoW (Diff: " + challenge.proofofwork.difficulty + ")");
            let solved = solvePoW(challenge.proofofwork.seed, challenge.proofofwork.difficulty, this.config);
            powAnswer = "gAAAAAB" + solved;
        }

        let token = await this.finalize(challenge, powAnswer);
        return { token: token, powAnswer: powAnswer };
    }

    async executeConversation(prompt, tokens) {
        let msgId = uuidv4();
        let now = Math.floor(Date.now() / 1000);
        let reqBody = {
            action: "next",
            messages: [{
                id: msgId,
                author: { role: "user" },
                content: { content_type: "text", parts: [prompt] },
                metadata: {
                    serialization_metadata: {
                        custom_symbol_offsets: []
                    }
                },
                create_time: now
            }],
            parent_message_id: uuidv4(),
            model: "auto",
            timezone_offset_min: -420,
            timezone: "Asia/Jakarta",
            history_and_training_disabled: true,
            is_visible: true,
            supported_encodings: ["v1"],
            supports_buffering: true,
            conversation_mode: { kind: "primary_assistant" },
            force_paragen_model_shuffle: false,
            force_paragen_model_request_override: "gpt-4o",
            force_use_search: false
        };

        let headers = this.getHeaders();
        headers["Accept"] = "text/event-stream";
        headers["openai-sentinel-chat-requirements-token"] = tokens.token;
        if (tokens.powAnswer) {
            headers["openai-sentinel-proof-token"] = tokens.powAnswer;
            headers["openai-sentinel-turnstile-token"] = tokens.powAnswer;
        }

        let fetchOpts = {
            method: "POST",
            headers: headers,
            body: JSON.stringify(reqBody),
            profile: "chrome_120"
        };
        if (this.proxyUrl) { fetchOpts.agent = this.proxyUrl; }
        if (this.fingerprint) { fetchOpts.fingerprint = this.fingerprint; }

        let resp = await fetch(this.baseURL + "/backend-anon/conversation", fetchOpts);

        // Capture fingerprint and cookies
        if (resp.fingerprint && resp.fingerprint.snapshoot) {
            this.fingerprint = resp.fingerprint.snapshoot();
            persistentFingerprint = this.fingerprint;
        }
        this.updateCookies(resp.headers);

        if (resp.status !== 200) {
            throw new Error("Conversation failed: " + resp.body);
        }

        return this.parseSSE(resp.body);
    }

    parseSSE(rawBody) {
        let lines = rawBody.split('\n');
        let fullText = "";

        for (let line of lines) {
            if (!line.startsWith("data: ")) continue;
            let data = line.substring(6).trim();
            if (data === "[DONE]") continue;

            try {
                let chunk = JSON.parse(data);

                // New multi-modal generic array patch format
                if (chunk.v && Array.isArray(chunk.v)) {
                    for (let op of chunk.v) {
                        if (op.o === "append" && typeof op.v === "string") {
                            fullText += op.v;
                        }
                    }
                }
                // Append string directly
                else if (chunk.o === "append" && typeof chunk.v === "string") {
                    fullText += chunk.v;
                }
                // Just string value
                else if (typeof chunk.v === "string" && !chunk.o) {
                    fullText += chunk.v;
                }
                // Legacy message response
                else if (chunk.message && chunk.message.content && chunk.message.content.parts) {
                    // Usually handled differently but just in case
                }
            } catch (e) {
                // Ignore parse errors on incomplete chunks
            }
        }

        if (fullText.length === 0) {
            throw new Error("No response body parsed");
        }

        return fullText;
    }
}

module.exports = {
    Client: ChatGPTClient
};
