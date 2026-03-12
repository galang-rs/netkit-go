// scripts/chatgpt/core/encoding.js
// Encoding utilities — UTF-8 bytes, Base64, FNV-1a hash

class Encoding {
    /**
     * Convert a JS string to a byte array using UTF-8 encoding.
     */
    static stringToBytes(str) {
        var bytes = [];
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c < 0x80) {
                bytes.push(c);
            } else if (c < 0x800) {
                bytes.push(0xC0 | (c >> 6));
                bytes.push(0x80 | (c & 0x3F));
            } else if (c >= 0xD800 && c <= 0xDBFF) {
                var hi = c;
                var lo = str.charCodeAt(++i);
                var cp = ((hi - 0xD800) << 10) + (lo - 0xDC00) + 0x10000;
                bytes.push(0xF0 | (cp >> 18));
                bytes.push(0x80 | ((cp >> 12) & 0x3F));
                bytes.push(0x80 | ((cp >> 6) & 0x3F));
                bytes.push(0x80 | (cp & 0x3F));
            } else {
                bytes.push(0xE0 | (c >> 12));
                bytes.push(0x80 | ((c >> 6) & 0x3F));
                bytes.push(0x80 | (c & 0x3F));
            }
        }
        return bytes;
    }

    /**
     * Base64 encode a JSON-stringified object.
     */
    static m1(t) {
        var s = JSON.stringify(t);
        var bytes = Encoding.stringToBytes(s);
        return Crypto.Base64Encode(bytes);
    }

    /**
     * FNV-1a hash — used for proof-of-work validation.
     */
    static fnv1a(t) {
        var e = 2166136261;
        for (var n = 0; n < t.length; n++) {
            e ^= t.charCodeAt(n);
            e = Math.imul(e, 16777619) >>> 0;
        }
        e ^= e >>> 16;
        e = Math.imul(e, 2246822507) >>> 0;
        e ^= e >>> 13;
        e = Math.imul(e, 3266489909) >>> 0;
        e ^= e >>> 16;
        return (e >>> 0).toString(16).padStart(8, '0');
    }
}

module.exports = Encoding;
