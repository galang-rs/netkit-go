// scripts/chatgpt/core/helpers.js
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
     * Decode image input from various formats into raw bytes + metadata.
     * Uses Crypto.Base64Decode / Crypto.HexDecode which return Go []byte
     * (exported as JS Uint8Array) — no UTF-8 corruption.
     *
     * Supports: data URI, base64, hex string, and HTTP(S) URL.
     *
     * @param {string} imageInput — Image data in any supported format
     * @param {string} [proxyUrl] — Optional proxy for URL fetching
     * @param {object} [fp]       — Optional fingerprint for URL fetching
     * @returns {{ data: Uint8Array, mimeType: string, fileName: string }}
     */
    static async decodeImageInput(imageInput, proxyUrl, fp) {
        // ── Data URI: data:image/png;base64,iVBOR... ──
        if (imageInput.indexOf('data:') === 0) {
            var semicolonIdx = imageInput.indexOf(';');
            var commaIdx = imageInput.indexOf(',');
            var mimeType = imageInput.substring(5, semicolonIdx);
            var b64Data = imageInput.substring(commaIdx + 1);
            var ext = mimeType.split('/')[1] || 'jpg';

            var bytes = Crypto.Base64Decode(b64Data);
            return {
                data: bytes,
                mimeType: mimeType,
                fileName: 'image.' + ext
            };
        }

        // ── HTTP(S) URL ──
        if (imageInput.indexOf('http://') === 0 || imageInput.indexOf('https://') === 0) {
            var fetchOpts = { method: 'GET' };
            if (proxyUrl) fetchOpts.agent = proxyUrl;
            if (fp) fetchOpts.fingerprint = fp;

            var resp = await fetch(imageInput, fetchOpts);
            if (!resp.ok) {
                throw new Error('Failed to fetch image from URL: HTTP ' + resp.status);
            }

            var contentType = resp.headers && resp.headers['content-type'];
            var urlMime = contentType ? contentType.split(';')[0].trim() : 'image/jpeg';

            // Extract filename from URL
            var urlParts = imageInput.split('/');
            var urlFileName = urlParts[urlParts.length - 1].split('?')[0] || 'image.jpg';

            // resp.bodyBytes is Go []byte — raw binary, no UTF-8 corruption
            var urlBytes = resp.bodyBytes;

            return {
                data: urlBytes,
                mimeType: urlMime,
                fileName: urlFileName
            };
        }

        // ── Hex string (even length, only 0-9a-fA-F) ──
        if (/^[0-9a-fA-F]+$/.test(imageInput) && imageInput.length % 2 === 0 && imageInput.length > 100) {
            var hexBytes = Crypto.HexDecode(imageInput);
            return {
                data: hexBytes,
                mimeType: Helpers.detectMimeFromBytes(hexBytes),
                fileName: 'image.' + Helpers.mimeToExt(Helpers.detectMimeFromBytes(hexBytes))
            };
        }

        // ── Base64 (fallback) ──
        var b64Bytes = Crypto.Base64Decode(imageInput);
        return {
            data: b64Bytes,
            mimeType: Helpers.detectMimeFromBytes(b64Bytes),
            fileName: 'image.' + Helpers.mimeToExt(Helpers.detectMimeFromBytes(b64Bytes))
        };
    }

    /**
     * Detect MIME type from the first bytes of raw image data.
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    static detectMimeFromBytes(bytes) {
        if (!bytes || bytes.length < 4) return 'image/jpeg';
        // PNG: 89 50 4E 47
        if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'image/png';
        // JPEG: FF D8 FF
        if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'image/jpeg';
        // GIF: 47 49 46 38
        if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) return 'image/gif';
        // WEBP: 52 49 46 46 ... 57 45 42 50
        if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
            bytes.length > 11 && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'image/webp';
        return 'image/jpeg';
    }

    /**
     * Convert MIME type to file extension.
     */
    static mimeToExt(mime) {
        if (mime === 'image/png') return 'png';
        if (mime === 'image/gif') return 'gif';
        if (mime === 'image/webp') return 'webp';
        return 'jpg';
    }
}

module.exports = Helpers;

