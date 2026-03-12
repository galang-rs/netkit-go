// scripts/chatgpt/config/constants.js
// Browser fingerprint defaults — fallback values when fingerprint.snapshoot() is unavailable

class Constants {
    static get chromeVersion() {
        return '144';
    }

    static get firefoxVersion() {
        return '146';
    }

    static get screenSizes() {
        return [
            1920 + 1080,
            1366 + 768,
            1440 + 900,
            1536 + 864,
            1280 + 720,
            1600 + 900,
            2560 + 1440,
            3840 + 2160
        ];
    }

    static get heapSizeLimits() {
        return [
            2147483648,
            4294967296,
            8589934592,
            17179869184,
            34359738368
        ];
    }

    static get heapToHardwareConcurrency() {
        return {
            2147483648: 2,
            4294967296: 4,
            8589934592: 8,
            17179869184: 16,
            34359738368: 32
        };
    }

    /**
     * Build the user-agent strings list using given browser versions.
     * @param {string} [chrome] — Chrome version override
     * @param {string} [firefox] — Firefox version override
     * @returns {string[]}
     */
    static userAgents(chrome, firefox) {
        var cv = chrome || Constants.chromeVersion;
        var fv = firefox || Constants.firefoxVersion;
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + cv + '.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + cv + '.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + cv + '.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + cv + '.0.0.0 Safari/537',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:' + fv + '.0) Gecko/20100101 Firefox/' + fv + '.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:' + fv + '.0) Gecko/20100101 Firefox/' + fv + '.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:' + fv + '.0) Gecko/20100101 Firefox/' + fv + '.0'
        ];
    }
}

module.exports = Constants;
