// scripts/mods/utils.js

function getNowLocal() {
    return new Date();
}

function formatLocalDate(date) {
    const pad = n => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
        `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function formatDiff(ms) {
    if (!ms || isNaN(ms)) return "0 detik";
    const h = Math.floor(ms / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    const s = Math.floor((ms % 60000) / 1000);
    if (h > 0) return `${h} jam ${m} menit`;
    if (m > 0) return `${m} menit ${s} detik`;
    return `${s} detik`;
}

module.exports = {
    getNowLocal,
    formatLocalDate,
    formatDiff
};
