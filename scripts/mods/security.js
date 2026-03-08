// scripts/mods/security.js

const RATE_LIMIT_CACHE_KEY = "rate_limit_store";
const GLOBAL_BLOCK_KEY = "global_block_state";

function getRateLimitStore() {
    const raw = FS.GetCache(RATE_LIMIT_CACHE_KEY);
    if (!raw) return {};
    try {
        // Handle both object and string (depending on engine behavior)
        if (typeof raw === 'object' && raw !== null) return raw;
        return JSON.parse(raw);
    } catch (e) {
        return {};
    }
}

function saveRateLimitStore(store) {
    // Force stringification to ensure persistence in Goja FS cache
    FS.SetCache(RATE_LIMIT_CACHE_KEY, JSON.stringify(store));
}

function isGlobalBlocked() {
    const state = FS.GetCache(GLOBAL_BLOCK_KEY);
    if (!state) return false;

    let parsedState = state;
    if (typeof state === 'string') {
        try { parsedState = JSON.parse(state); } catch (e) { return false; }
    }

    if (Date.now() > parsedState.until) {
        FS.SetCache(GLOBAL_BLOCK_KEY, null);
        return false;
    }
    return true;
}

function setGlobalBlock(minutes) {
    FS.SetCache(GLOBAL_BLOCK_KEY, JSON.stringify({ until: Date.now() + minutes * 60 * 1000 }));
}

function checkRateLimit(ip, endpoint, limit, windowMs, caller = "unknown") {
    const store = getRateLimitStore();
    const now = Date.now();
    const key = `${ip}:${endpoint}`;

    if (!store[key]) store[key] = [];

    // Filter out old timestamps
    store[key] = store[key].filter(t => now - t < windowMs);

    if (store[key].length >= limit) {
        saveRateLimitStore(store);
        return false;
    }

    store[key].push(now);
    saveRateLimitStore(store);
    return true;
}

module.exports = {
    isGlobalBlocked,
    setGlobalBlock,
    checkRateLimit
};
