// scripts/mods/state.js

const state = {
    countPlayer: 0,
    banRate: 0.0,
    serverMaintance: false,
    nukeWorld: 0,
    banPlayer: 0,
    modsCache: { mods: [] },
    modsCacheOriginal: [],
    lastUpdate: "",
    lastUpdateTime: null,
    globalRequestCount: 0,
    cumulativeRequestCount: 0,
    rawDataMods: {},
    defaultParams: [],
    defaultParamsUndercover: [],
    proxies: [],
    currentIndex: 0,
    countPlayerLog: { historyPlayer: [] },
    previousModsStatus: new Map(),
    statusHistory: new Map(),
    messageIdMap: new Map(),
    modLogs: {},
    proxyResponse: {},
    playtimeServer: "",
    reasonMaintance: "",
    lastDate: -1,
    startTime: Date.now()
};

module.exports = state;
