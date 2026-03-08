const { config, loadJsonFile, saveJsonFile, proxies } = require('./config.js');
const { getNowLocal, formatLocalDate } = require('./utils.js');
const { postModStart, patchModOffline, updateStatusEmbeds, updateBotStatusEmbed, sendStuckAlert } = require('./discord.js');
const state = require('./state.js');

function formatHistory() {
    const now = getNowLocal();
    const days = ["Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"];
    const dayName = days[now.getDay()];
    const dd = String(now.getDate()).padStart(2, "0");
    const mm = String(now.getMonth() + 1).padStart(2, "0");
    const hh = String(now.getHours()).padStart(2, "0");
    const min = String(now.getMinutes()).padStart(2, "0");
    const ss = String(now.getSeconds()).padStart(2, "0");

    return `[${dayName} ${dd}/${mm} ${hh}:${min}:${ss}] Player : ${state.countPlayer} | Ban Rate : ${(state.banRate).toFixed(2)} | Banned Player : ${state.banPlayer} | Nuked World : ${state.nukeWorld}`;
}

async function logPlayer() {
    try {
        if (state.countPlayerLog.historyPlayer.length === 0) {
            state.countPlayerLog = loadJsonFile("logPlayer.json", { historyPlayer: [] });
        }
        if (!Array.isArray(state.countPlayerLog.historyPlayer)) {
            state.countPlayerLog.historyPlayer = [];
        }
        state.countPlayerLog.historyPlayer.unshift(formatHistory());
        if (state.countPlayerLog.historyPlayer.length > 44640) {
            state.countPlayerLog.historyPlayer.pop();
        }
        saveJsonFile("logPlayer.json", state.countPlayerLog);
    } catch (error) {
        console.error("Error in logPlayer:", error);
    }
}

async function loadModData() {
    const cfg = config();
    let mods = [];

    try {
        const fileContent = FS.ReadString(`${cfg.paths.baseDir}/${cfg.paths.data.modsOnline}`);
        const jsonData = JSON.parse(fileContent);

        if (Array.isArray(jsonData.mods)) {
            const lud = jsonData.lastUpdate || jsonData.last_update || state.lastUpdate;
            state.lastUpdate = lud;

            // Handle different date formats more robustly
            if (lud) {
                let dateStr = lud;
                // If it's "YYYY-MM-DD HH:mm:ss", treat it as local time, don't force 'Z'
                if (!dateStr.includes('T') && dateStr.includes(' ')) {
                    dateStr = dateStr.replace(' ', 'T');
                }
                state.lastUpdateTime = new Date(dateStr);
                if (isNaN(state.lastUpdateTime.getTime())) {
                    state.lastUpdateTime = new Date(lud); // Final fallback
                }
            }

            state.banRate = parseFloat(jsonData.ban_rate || jsonData.banRate || 0.0);
            state.serverMaintance = jsonData.server_maintance || jsonData.maintenance || false;
            state.reasonMaintance = jsonData.reason_server_maintance || "";
            state.nukeWorld = jsonData.nuked || jsonData.nuke_world || 0;
            state.banPlayer = jsonData.ban || jsonData.ban_player || 0;
            state.countPlayer = jsonData.player_count || jsonData.count_player || state.countPlayer;
            state.playtimeServer = jsonData.playtime_server || "";

            mods = jsonData.mods.map(m => ({
                name: m.name ?? "unknown",
                role: m.role ?? 1,
                updated: m.updated ?? 0,
                undercover: m.undercover ? "iya" : "tidak",
                idle: m.idle ? "iya" : "tidak"
            })) || [];

            // Update modsStatus
            const nowUnix = Math.floor(Date.now() / 1000);
            const newStatus = {};
            const previousStatus = loadJsonFile(`${cfg.paths.baseDir}/${cfg.paths.data.modsStatus}`, {});

            for (const mod of jsonData.mods) {
                const modName = mod.name.toLowerCase();
                const existing = previousStatus[modName];
                const onlineSince = (existing?.online && existing?.onlineSince) ? existing.onlineSince : nowUnix;

                const isUndercover = !!mod.undercover && mod.undercover !== "tidak";
                const isIdle = !!mod.idle && mod.idle !== "tidak";

                newStatus[modName] = {
                    name: mod.name,
                    online: true,
                    undercover: isUndercover,
                    idle: isIdle,
                    role: mod.role ?? 1,
                    status: isUndercover ? "undercover" : (isIdle ? "idle" : "online"),
                    lastUpdate: mod.updated || nowUnix,
                    onlineSince
                };
            }

            for (const [prevName, prevData] of Object.entries(previousStatus)) {
                if (!(prevName in newStatus)) {
                    const timeSinceLastSeen = nowUnix - (prevData.lastUpdate || nowUnix);
                    newStatus[prevName] = {
                        name: prevData.name || prevName,
                        online: false,
                        undercover: prevData.undercover,
                        idle: (timeSinceLastSeen <= 600),
                        role: prevData.role ?? 1,
                        status: "offline",
                        lastUpdate: prevData.lastUpdate || nowUnix
                    };
                }
            }
            saveJsonFile(`${cfg.paths.baseDir}/${cfg.paths.data.modsStatus}`, newStatus);
            state.modsCache.mods = mods;
            state.modsCacheOriginal = jsonData;
            return { mods: Object.values(newStatus), raw: jsonData };
        }
    } catch (e) {
        console.error(`❌ Error reading ${cfg.paths?.data?.modsOnline}:`, e.message || e);
    }
    return { mods: [], raw: {} };
}

async function updateSlot() {
    const cfg = config();
    const now = getNowLocal();
    const nowTime = now.getTime();

    // 1. Request Fresh Player Count via Proxy
    const onlineUser = await requestWithNextProxy();

    // 2. Load Data
    const { mods: modsStatusArray } = await loadModData();

    // 2. Track Online/Offline Events for Mod Log
    for (const mod of modsStatusArray) {
        const isOnline = mod.status !== 'offline';
        const wasOnline = state.previousModsStatus.has(mod.name);

        if (isOnline && !wasOnline) {
            const messageId = await postModStart(mod.name, mod.status, nowTime);
            state.messageIdMap.set(mod.name, messageId);
            state.previousModsStatus.set(mod.name, nowTime);
            state.statusHistory.set(mod.name, [{ status: mod.status, time: nowTime }]);
        } else if (isOnline && wasOnline) {
            const history = state.statusHistory.get(mod.name) || [];
            if (history.length > 0 && history[history.length - 1].status !== mod.status) {
                history.push({ status: mod.status, time: nowTime });
            }
        } else if (!isOnline && wasOnline) {
            const startTime = state.previousModsStatus.get(mod.name);
            const history = state.statusHistory.get(mod.name) || [];
            const messageId = state.messageIdMap.get(mod.name);
            await patchModOffline(messageId, mod.name, history, startTime, nowTime);
            state.previousModsStatus.delete(mod.name);
            state.statusHistory.delete(mod.name);
            state.messageIdMap.delete(mod.name);
        }
    }

    // 3. Update modLogs (for charts)
    const hour = now.getHours();
    const minute = now.getMinutes();
    const index = hour * 60 + minute;

    if (!state.modLogs.player_count) state.modLogs.player_count = [];
    if (!state.modLogs.world_nuke_and_ban) state.modLogs.world_nuke_and_ban = [];

    state.modLogs.player_count = state.modLogs.player_count.filter(e => Math.abs(e.index - index) > 2);
    state.modLogs.world_nuke_and_ban = state.modLogs.world_nuke_and_ban.filter(e => Math.abs(e.index - index) > 2);

    state.modLogs.player_count.push({ index, count: state.countPlayer });
    state.modLogs.world_nuke_and_ban.push({ index, count: state.nukeWorld + state.banPlayer });

    if (minute % 5 === 0) {
        const { saveModLogs } = require('./config.js');
        saveModLogs(state.modLogs);
    }

    // 4. Send Discord status updates
    // Determine the reporting reason like source.js
    let reportingReason = null;
    if (state.lastUpdateTime && nowTime - state.lastUpdateTime.getTime() > 60 * 60 * 1000) {
        reportingReason = "bot check mod offline / erkon pls wait or change ip";
    }

    await updateStatusEmbeds(modsStatusArray, {
        nuked: state.nukeWorld,
        ban: state.banPlayer,
        players: state.countPlayer,
        uptime: state.playtimeServer,
        maintenance: state.serverMaintance,
        reason: state.reasonMaintance
    }, reportingReason);

    // 5. Bot Status Embed
    await updateBotStatusEmbed(
        { isOffline: reportingReason !== null, totalMinutes: 0, restMinutes: 0, playMinutes: 0 },
        reportingReason || "Operational",
        { web: onlineUser, growtopia: state.countPlayer },
        state.serverMaintance,
        state.reasonMaintance,
        state.lastUpdateTime || now
    );

    // 6. Stuck Alert
    if (state.lastUpdateTime) {
        await sendStuckAlert(state.lastUpdateTime, reportingReason || "Operational");
    }

    await logPlayer();
}

async function requestWithNextProxy() {
    const cfg = config();
    const proxyList = proxies();

    if (!cfg.app?.features?.proxyRotation || proxyList.length === 0) return;

    try {
        const proxyStr = proxyList[state.currentIndex];
        const p = proxyStr.split(':');
        let proxyUrl = "";
        if (p.length >= 4) {
            proxyUrl = `socks5://${p[2]}:${p[3]}@${p[0]}:${p[1]}`;
        } else if (p.length >= 2) {
            proxyUrl = `socks5://${p[0]}:${p[1]}`;
        }

        const resp = await fetch('https://www.growtopiagame.com/detail', {
            method: 'GET',
            profile: 'chrome_120',
            proxy: proxyUrl
        });

        if (resp.ok) {
            const data = JSON.parse(resp.body);
            state.proxyResponse = data; // Save the full response

            const onlineRaw = data.online_user || 0;
            // Robust parsing: remove commas and any non-numeric chars except decimals
            const online = parseInt(String(onlineRaw).replace(/,/g, ''));

            if (!isNaN(online) && online > 0) {
                state.countPlayer = online;
            }
        }
        return resp.body.online_user;
    } catch (err) {
        console.error(`Failed to fetch online users: ${err}`);
    } finally {
        state.currentIndex = (state.currentIndex + 1) % proxyList.length;
    }
}

async function runTasks() {
    const cfg = config();
    const now = getNowLocal();

    if (now.getDate() !== state.lastDate) {
        state.lastDate = now.getDate();
    }

    await updateSlot();
}

module.exports = {
    runTasks,
    loadModData,
    updateSlot,
    logPlayer,
    requestWithNextProxy
};
