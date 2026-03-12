// scripts/chatgpt/services/sse-parser.js
// Server-Sent Events response parser for ChatGPT conversation API

class SSEParser {
    /**
     * Parse SSE response body and extract the full assistant message.
     * Supports both v1 buffered encoding (append/patch ops) and standard SSE.
     *
     * @param {string} body — Raw SSE response body
     * @returns {{ text: string, raw: string, dataLineCount: number }}
     */
    static parse(body) {
        var normalized = body.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

        var allDataLines = normalized.split('\n')
            .filter(function (line) { return line.indexOf('data: ') === 0; })
            .map(function (line) { return line.substring(6).trim(); })
            .filter(function (line) { return line !== '[DONE]' && line.length > 0; });

        if (allDataLines.length === 0) {
            return { text: '', raw: body.substring(0, 500), dataLineCount: 0 };
        }

        console.log('[SSE] Data lines: ' + allDataLines.length);

        // ── Strategy 1: v1 buffered encoding (append/patch operations) ──
        var v1Response = '';
        var hasV1 = false;

        for (var i = 0; i < allDataLines.length; i++) {
            try {
                var json = JSON.parse(allDataLines[i]);
                if (typeof json !== 'object' || json === null) continue;

                if (json.o === 'append' && typeof json.v === 'string') {
                    v1Response += json.v;
                    hasV1 = true;
                }
                if (json.o === 'patch' && Array.isArray(json.v)) {
                    for (var j = 0; j < json.v.length; j++) {
                        var entry = json.v[j];
                        if (entry && entry.o === 'append' && typeof entry.v === 'string') {
                            v1Response += entry.v;
                            hasV1 = true;
                        }
                    }
                }
                if (typeof json.v === 'string' && !json.o) {
                    v1Response += json.v;
                    hasV1 = true;
                }
            } catch (e) {
                // Not valid JSON
            }
        }

        // ── Strategy 2: Standard SSE (message.content.parts) ──
        var sseResponse = '';
        for (var k = allDataLines.length - 1; k >= 0; k--) {
            try {
                var evt = JSON.parse(allDataLines[k]);
                if (!evt || typeof evt !== 'object') continue;

                if (evt.message && evt.message.content && Array.isArray(evt.message.content.parts)) {
                    var parts = evt.message.content.parts;
                    var fullText = '';
                    for (var p = 0; p < parts.length; p++) {
                        if (typeof parts[p] === 'string') fullText += parts[p];
                    }
                    if (fullText.length > sseResponse.length) {
                        sseResponse = fullText;
                    }
                }

                if (evt.parts && Array.isArray(evt.parts)) {
                    var partsText = '';
                    for (var q = 0; q < evt.parts.length; q++) {
                        if (typeof evt.parts[q] === 'string') partsText += evt.parts[q];
                    }
                    if (partsText.length > sseResponse.length) {
                        sseResponse = partsText;
                    }
                }
            } catch (e) {
                // Skip
            }
        }

        // Use whichever strategy yielded the longest response
        var finalText = '';
        if (hasV1 && v1Response.length >= sseResponse.length) {
            finalText = v1Response;
            console.log('[SSE] Using v1 buffered response (' + finalText.length + ' chars)');
        } else if (sseResponse.length > 0) {
            finalText = sseResponse;
            console.log('[SSE] Using message.content.parts response (' + finalText.length + ' chars)');
        } else {
            finalText = v1Response;
            console.log('[SSE] Fallback response (' + finalText.length + ' chars)');
        }

        return { text: finalText, raw: body.substring(0, 500), dataLineCount: allDataLines.length };
    }
}

module.exports = SSEParser;
