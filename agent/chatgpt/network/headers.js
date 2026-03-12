// scripts/chatgpt/network/headers.js
// HTTP headers builder for ChatGPT API requests

const Helpers = require('../core/helpers.js');
const Constants = require('../config/constants.js');

class Headers {
    /**
     * Build default headers for ChatGPT API requests.
     *
     * @param {Array} config       — Browser config array from Fingerprint.getConfig()
     * @param {string} deviceId    — Device ID (UUID)
     * @param {string} oaiBuildId  — OpenAI build ID
     * @param {object} [extra]     — Additional headers to merge
     * @returns {object} Headers object
     */
    static build(config, deviceId, oaiBuildId, extra) {
        var headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json',
            'Cookie': 'oai-did=' + deviceId,
            'Oai-Build-Id': oaiBuildId || Helpers.randomNumber(1000000000, 9999999999).toString(),
            'Oai-Client-Version': config[6] || '',
            'Oai-DeviceId': deviceId,
            'Oai-Language': config[8] || 'en-US',
            'Origin': 'https://chatgpt.com',
            'Referer': 'https://chatgpt.com/',
            'User-Agent': config[4] || Helpers.randomPick(Constants.userAgents())
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
