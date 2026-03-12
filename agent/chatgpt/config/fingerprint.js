// scripts/chatgpt/config/fingerprint.js
// Config array generator — builds browser fingerprint config for sentinel auth
// Uses fingerprint.snapshoot() values by default, falls back to Constants pool

const Helpers = require('../core/helpers.js');
const Constants = require('./constants.js');
const navigatorKeys = require('../keys/navigator.js');
const windowKeys = require('../keys/window.js');

class Fingerprint {
    /**
     * Build the browser config array used for sentinel proof & headers.
     *
     * @param {string} gptHomepage — Raw HTML of ChatGPT homepage
     * @param {object} [snapshot]  — Optional fingerprint.snapshoot() object.
     *   When present, its values override the random defaults:
     *     snapshot.userAgent    → config[4]
     *     snapshot.screenSize   → config[0]
     *     snapshot.heapSizeLimit → config[2]
     *     snapshot.version      → used to build user-agent list
     * @returns {Array} 16-element config array
     */
    static getConfig(gptHomepage, snapshot) {
        var allNumbers = '0123456789';
        var randomStringOf15Numbers = '';
        for (var i = 0; i < 15; i++) {
            randomStringOf15Numbers += allNumbers[Math.floor(Math.random() * allNumbers.length)];
        }

        // ── Resolve values: snapshot overrides → random fallback ──
        var userAgentList = Constants.userAgents(
            (snapshot && snapshot.version) || null,
            null
        );

        var userAgent   = (snapshot && snapshot.userAgent)    || Helpers.randomPick(userAgentList);
        var screenSize  = (snapshot && snapshot.screenSize)   || Helpers.randomPick(Constants.screenSizes);
        var heapLimit   = (snapshot && snapshot.heapSizeLimit) || Helpers.randomPick(Constants.heapSizeLimits);

        var chosenNaviKey = Helpers.randomPick(navigatorKeys);
        var nowMs = Date.now();

        var buildMatch = gptHomepage.match(/data-build="([^"]+)"/);
        var buildId = buildMatch ? buildMatch[1] : 'prod-' + Helpers.generateUUID();

        return [
            screenSize,                                                             // [0] screen size
            '' + new Date(),                                                        // [1] date string
            heapLimit,                                                              // [2] heap size limit
            1,                                                                      // [3] counter (overwritten in PoW)
            userAgent,                                                              // [4] user agent
            'https://www.googletagmanager.com/gtag/js?id=G-9SHBSK2D9J',           // [5] gtag URL
            buildId,                                                                // [6] build ID
            'en-US',                                                                // [7] language
            'en-US',                                                                // [8] language 2
            nowMs - Number('1.' + randomStringOf15Numbers),                         // [9] performance.now offset
            chosenNaviKey + '\u2212function ' + chosenNaviKey + '() { [native code] }', // [10] navigator key proof
            'document',                                                             // [11] document
            Helpers.randomPick(windowKeys),                                         // [12] window key
            nowMs + Helpers.randomNumber(0, 1000),                                  // [13] performance.now
            Constants.heapToHardwareConcurrency[heapLimit],                         // [14] hardware concurrency
            Date.now() - Helpers.randomNumber(100000, 500000)                       // [15] timestamp offset
        ];
    }
}

module.exports = Fingerprint;
