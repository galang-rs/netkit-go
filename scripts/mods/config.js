// scripts/mods/config.js

let _config = {};
let _rawDataMods = {};
let _defaultParams = [];
let _defaultParamsUndercover = [];
let _proxies = [];

function loadJsonFile(filePath, defaultValue) {
    try {
        const content = FS.ReadString(filePath);
        return JSON.parse(content);
    } catch (e) {
        // console.error(`Gagal membaca JSON dari ${filePath}`);
        return defaultValue;
    }
}

function saveJsonFile(filePath, data) {
    try {
        FS.SaveFile(filePath, JSON.stringify(data, null, 4));
    } catch (e) {
        console.error(`Gagal menyimpan ke ${filePath}:`, e);
    }
}

function loadConfig() {
    try {
        const configDirs = FS.ListDir("config");
        if (!configDirs || !Array.isArray(configDirs)) {
            console.error('❌ Gagal melist direktori config atau direktori tidak ditemukan.');
            return;
        }

        for (const item of configDirs) {
            // Cek apakah item adalah string atau objek dengan properti name/Name
            const fileName = typeof item === 'string' ? item : (item.name || item.Name);

            if (fileName && fileName.endsWith('.json')) {
                const filePath = `config/${fileName}`;
                const fileContent = FS.ReadString(filePath);
                const key = fileName.replace('.json', '');
                _config[key] = JSON.parse(fileContent);
            }
        }

        _rawDataMods = _config.mods?.rawDataMods || {};
        _defaultParams = _config.mods?.defaultParams || [];
        _defaultParamsUndercover = _config.mods?.defaultParamsUndercover || [];
        _proxies = _config.proxies?.list || [];

    } catch (error) {
        console.error('❌ Gagal memuat konfigurasi:', error.message || error);
    }
}

function loadModLogs() {
    if (!_config.paths) return {};
    return loadJsonFile(`${_config.paths.baseDir}/${_config.paths.data.modLogs}`, {});
}

function saveModLogs(logs) {
    if (!_config.paths) return;
    return saveJsonFile(`${_config.paths.baseDir}/${_config.paths.data.modLogs}`, logs);
}

module.exports = {
    _config: () => _config, // Internal ref for debugging if needed
    config: () => _config,
    rawDataMods: () => _rawDataMods,
    defaultParams: () => _defaultParams,
    defaultParamsUndercover: () => _defaultParamsUndercover,
    proxies: () => _proxies,
    loadConfig,
    loadJsonFile,
    saveJsonFile,
    loadModLogs,
    saveModLogs
};
