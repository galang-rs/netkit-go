// agent/duckduckgo/core/helpers.js
// Core helper utilities — random, UUID generation

class Helpers {
    static randomNumber(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    static randomPick(arr) {
        return arr[Math.floor(Math.random() * arr.length)];
    }

    static generateUUID() {
        var hex = Crypto.RandomHex(16);
        return hex.substring(0, 8) + '-' +
            hex.substring(8, 12) + '-' +
            '4' + hex.substring(13, 16) + '-' +
            ((parseInt(hex.substring(16, 17), 16) & 0x3 | 0x8).toString(16)) + hex.substring(17, 20) + '-' +
            hex.substring(20, 32);
    }

    /**
     * Encode query string for URL use.
     * @param {string} str
     * @returns {string}
     */
    static encodeQuery(str) {
        return encodeURIComponent(str).replace(/%20/g, '+');
    }
}

module.exports = Helpers;
