// scripts/mods/discord.js
const { config } = require('./config.js');
const { formatDiff } = require('./utils.js');
const state = require('./state.js');

async function postModStart(modName, status, startTime) {
    const cfg = config();
    if (!cfg.app?.features?.discordWebhooks || !cfg.discord?.webhooks?.modLog?.enabled) return null;

    const content = [
        `**GrowID:** ${modName}`,
        `**Online time:** ${new Date(startTime).toLocaleString("en-US", { timeZone: "Asia/Jakarta" })}`,
        `**Start Status:** ${status}`,
        `**Status history:**\n- ${status} (0 detik)`
    ].join("\n");

    try {
        const res = await fetch(`${cfg.discord.webhooks.modLog.url}?wait=true`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        const data = JSON.parse(res.body);
        return data.id;
    } catch (err) {
        console.error("[Discord] POST mod log failed:", err);
        return null;
    }
}

async function patchModOffline(messageId, modName, history, startTime, offlineTime) {
    const cfg = config();
    if (!cfg.app?.features?.discordWebhooks || !cfg.discord?.webhooks?.modLog?.enabled || !messageId) return;

    let timeline = history
        .map((h, i) => {
            const next = history[i + 1] || { time: offlineTime };
            return `- ${h.status} (${formatDiff(next.time - h.time)})`;
        })
        .join("\n");

    const totalPlay = formatDiff(offlineTime - startTime);
    const content = [
        `**GrowID:** ${modName}`,
        `**Online time:** ${new Date(startTime).toLocaleString("en-US", { timeZone: "Asia/Jakarta" })}`,
        `**Offline time:** ${new Date(offlineTime).toLocaleString("en-US", { timeZone: "Asia/Jakarta" })}`,
        `**Status history:**\n${timeline}`,
        `**Total playing:** ${totalPlay}`
    ].join("\n");

    try {
        await fetch(`${cfg.discord.webhooks.modLog.url}/messages/${messageId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
    } catch (err) {
        console.error("[Discord] PATCH mod log offline failed:", err);
    }
}

async function updateStatusEmbeds(mods, stats, reason = null) {
    const cfg = config();
    if (!cfg.app?.features?.discordWebhooks) return;

    const updatedUnix = Math.floor(Date.now() / 1000);
    const roleMap = { 0: ':man_technologist: Developer', 1: ':shield: Moderator', 2: ':nazar_amulet: Guardian' };

    const generateModListString = (typeMods, behavior = 'online') => {
        const statuses = behavior === 'online' ? ['online', 'undercover', 'idle'] : ['offline'];
        const titles = { online: ':green_circle: Online', undercover: ':detective: Undercover', idle: ':orange_circle: Idle', offline: ':red_circle: Offline' };
        const sections = { online: [], undercover: [], idle: [], offline: [] };

        const monthInSeconds = 30 * 24 * 60 * 60; // 30 days

        for (const m of typeMods) {
            const roleName = roleMap[m.role] || 'Unknown';
            // Use lastUpdate for everyone so it shows the "last sync" time (e.g. 5 minutes ago)
            const timeRef = Math.floor(Number(m.lastUpdate) || updatedUnix);

            // Filter offline mods (last 30 days only)
            if (behavior === 'offline' && (updatedUnix - timeRef > monthInSeconds)) {
                continue;
            }

            sections[m.status].push(`${roleName} **${m.name}** <t:${timeRef}:R>`);
        }

        let output = "";
        for (const s of statuses) {
            output += `\n**${titles[s]}**\n`;
            if (sections[s].length > 0) {
                output += sections[s].join('\n') + '\n';
            } else {
                output += '_Tidak ada_\n';
            }
        }
        return output;
    };

    const payloadOnline = {
        content: null,
        embeds: [{
            title: ':green_circle: Mods Online Status',
            color: 0x2ECC71,
            description: [
                `:clock3: **Updated:** <t:${updatedUnix}:F>`,
                `:stopwatch: **Relative:** <t:${updatedUnix}:R>`,
                generateModListString(mods.filter(m => m.status !== 'offline'), 'online')
            ].join('\n').substring(0, 4000),
            footer: { text: 'Mod status updated automatically' },
            timestamp: new Date().toISOString()
        }]
    };
    if (reason === "bot check mod offline / erkon pls wait or change ip") {
        payloadOnline.content = "Bot check mod offline atau Erkon, silakan tunggu";
    }

    const payloadOffline = {
        content: null,
        embeds: [{
            title: ':red_circle: Mods Offline Status',
            color: 0xE74C3C,
            description: [
                `:clock3: **Updated:** <t:${updatedUnix}:F>`,
                `:stopwatch: **Relative:** <t:${updatedUnix}:R>`,
                generateModListString(mods.filter(m => m.status === 'offline'), 'offline')
            ].join('\n').substring(0, 4000),
            footer: { text: 'Mod offline status updated automatically' },
            timestamp: new Date().toISOString()
        }]
    };

    const payloadLog = {
        content: null,
        embeds: [{
            title: ':bar_chart: Activity Logs',
            color: 0x3498DB,
            description: [
                `:clock3: **Updated:** <t:${updatedUnix}:F>`,
                `:stopwatch: **Relative:** <t:${updatedUnix}:R>`,
                "\n**:chart_with_upwards_trend: Server Activity**",
                `> :fire: **Nuked (last 30 min):** ${stats.nuked}`,
                `> :hammer: **Banned (last 30 min):** ${stats.ban}`,
                `> :busts_in_silhouette: **Players Online:** ${stats.players}`,
                `> :hourglass_flowing_sand: **Server Uptime:** ${stats.uptime}`,
                `> :tools: **Maintenances:** ${stats.maintenance ? `Yes, \`${stats.reason?.trim()}\`` : 'No'}`
            ].join('\n'),
            footer: { text: 'Activity logs updated automatically' },
            timestamp: new Date().toISOString()
        }]
    };

    const webhooks = cfg.discord?.webhooks?.modStatus;
    if (webhooks?.enabled) {
        const configs = [];

        // Primary Webhook
        if (webhooks.id && webhooks.token && webhooks.messages) {
            const prefix = `https://discord.com/api/webhooks/${webhooks.id}/${webhooks.token}/messages`;
            const msgs = webhooks.messages;
            if (msgs.online) configs.push({ url: `${prefix}/${msgs.online}`, payload: payloadOnline });
            if (msgs.offline) configs.push({ url: `${prefix}/${msgs.offline}`, payload: payloadOffline });
            if (msgs.log) configs.push({ url: `${prefix}/${msgs.log}`, payload: payloadLog });
        }

        // Secondary Webhook
        if (webhooks.id1 && webhooks.token1 && webhooks.messages1) {
            const prefix = `https://discord.com/api/webhooks/${webhooks.id1}/${webhooks.token1}/messages`;
            const msgs = webhooks.messages1;
            if (msgs.online) configs.push({ url: `${prefix}/${msgs.online}`, payload: payloadOnline });
            if (msgs.offline) configs.push({ url: `${prefix}/${msgs.offline}`, payload: payloadOffline });
            if (msgs.log) configs.push({ url: `${prefix}/${msgs.log}`, payload: payloadLog });
        }

        try {
            await Promise.all(configs.map(async ({ url, payload }) => {
                const res = await fetch(url, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (!res.ok) {
                    console.error(`[Discord] PATCH failed for ${url}: ${res.status} ${res.body}`);
                    console.error(`[Discord] Payload head: ${JSON.stringify(payload).substring(0, 400)}`);
                }
            }));
        } catch (e) {
            console.error("[Discord] Error patching status webhooks:", e.message);
        }
    }
}

async function updateBotStatusEmbed(botStatus, reason, players, maintenance, maintenanceReason, lastUpdateTime) {
    const cfg = config();
    if (!cfg.app?.features?.discordWebhooks || !cfg.discord?.webhooks?.botStatus?.enabled) return;

    const updatedUnix = Math.floor(Date.now() / 1000);
    const totalMinutes = botStatus.totalMinutes;
    const hours = Math.floor(totalMinutes / 60);
    const minutes = totalMinutes % 60;
    const restHours = Math.floor(botStatus.restMinutes / 60);
    const restMinutes = botStatus.restMinutes % 60;
    const playHours = Math.floor(botStatus.playMinutes / 60);
    const playMinutes = botStatus.playMinutes % 60;

    try {
        await fetch(`https://discord.com/api/webhooks/${cfg.discord.webhooks.botStatus.id}/${cfg.discord.webhooks.botStatus.token}/messages/${cfg.discord.webhooks.botStatus.messageId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                embeds: [{
                    title: ':satellite: Bot Status',
                    color: 0x1ABC9C,
                    description: `:clock3: **Updated:** <t:${updatedUnix}:F>\n:stopwatch: **Relative:** <t:${updatedUnix}:R>`,
                    fields: [{
                        name: ':fire: System Log',
                        value: [
                            `**Status Bot:** ${botStatus.isOffline ? ':red_circle: Offline' : ':green_circle: Online'}`,
                            `**Reason:** ${reason || 'None'}`,
                            `**Players:**`,
                            `> :globe_with_meridians: **WEB**: ${players.web || (state.proxyResponse && state.proxyResponse.online_user) || 0}`,
                            `> :video_game: **GT**: ${players.growtopia || 0}`,
                            `**Maintenances:** ${maintenance ? `:tools: Yes, \`${maintenanceReason.trim()}\`` : '✅ No'}`,
                            `**Last Local Update:**\n> :calendar_spiral: ${lastUpdateTime.toLocaleString('id-ID', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false })}`
                        ].join('\n')
                    }, {
                        name: ':hourglass_flowing_sand: Runtime Summary',
                        value: [
                            `:green_square: **Playtime:** ${playHours} jam ${playMinutes} menit`,
                            `:red_square: **Resttime:** ${restHours} jam ${restMinutes} menit`,
                            `:chart_with_upwards_trend: **Total Runtime:** ${hours} jam ${minutes} menit`
                        ].join('\n')
                    }],
                    footer: { text: 'Status monitoring provided by your bot' },
                    timestamp: new Date().toISOString()
                }]
            })
        });
    } catch (err) {
        console.error('[Discord] Error patching bot status webhook:', err.message);
    }
}

async function sendStuckAlert(lastUpdateTime, reason) {
    const cfg = config();
    if (!cfg.app?.features?.discordWebhooks || !cfg.discord?.webhooks?.stuckAlert?.enabled) return;

    try {
        const diffMinutes = (Date.now() - lastUpdateTime.getTime()) / 1000 / 60;
        if (diffMinutes % 30 < 1 && reason === "bot check mod offline / erkon pls wait or change ip") {
            await fetch(cfg.discord.webhooks.stuckAlert.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: `${cfg.discord.webhooks.stuckAlert.targetUser} bang macet scnya coba perbaiki` })
            });
        }
    } catch (err) {
        console.error('[Discord] Error sending stuck webhook:', err.message);
    }
}

module.exports = {
    postModStart,
    patchModOffline,
    updateStatusEmbeds,
    updateBotStatusEmbed,
    sendStuckAlert
};
