// agent/duckduckgo/network/headers.js
// HTTP headers builder — minimal, for DuckDuckGo requests
// (Kept for compatibility, but DDG uses simpler headers in search service)

const Helpers = require('../core/helpers.js');
const Constants = require('../config/constants.js');

class Headers {
    /**
     * Build browser-like headers.
     * @param {object} [extra]
     * @returns {object}
     */
    static build(extra) {
        var headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'User-Agent': Helpers.randomPick(Constants.userAgents()),
            'Upgrade-Insecure-Requests': '1'
        };
        if (extra) {
            for (var k in extra) {
                headers[k] = extra[k];
            }
        }
        return headers;
    }
}

module.exports = Headers;
