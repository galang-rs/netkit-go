let globalConfig = {
    proxyUrl: ""
};

module.exports = {
    set: function (cfg) {
        globalConfig = Object.assign(globalConfig, cfg);
    },
    get: function () {
        return globalConfig;
    }
};
