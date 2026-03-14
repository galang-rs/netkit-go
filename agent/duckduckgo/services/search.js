// agent/duckduckgo/services/search.js
// DuckDuckGo Search HTTP service
// Uses html.duckduckgo.com — designed for non-JS clients, no blocks

const Helpers = require('../core/helpers.js');

class SearchService {
    /**
     * Search DuckDuckGo using its HTML-only endpoint.
     * html.duckduckgo.com returns full search results without JavaScript.
     *
     * @param {string} query
     * @param {string} [proxyUrl] — Optional SOCKS5 proxy URL
     * @param {object} [fp] — Optional fingerprint
     * @returns {{ success: boolean, html?: string, error?: string }}
     */
    static async search(query, proxyUrl, fp) {
        var url = 'https://html.duckduckgo.com/html/?q=' + Helpers.encodeQuery(query);

        console.log('[DDG] Fetching: ' + url.substring(0, 100) + '...');

        var fetchOpts = {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Upgrade-Insecure-Requests': '1'
            },
            profile: 'chrome'
        };

        if (proxyUrl) fetchOpts.agent = proxyUrl;
        if (fp) fetchOpts.fingerprint = fp;

        var resp = await fetch(url, fetchOpts);

        if (!resp.ok) {
            return { success: false, error: 'DuckDuckGo HTTP ' + resp.status };
        }

        var html = resp.body || '';

        if (html.length < 200) {
            return { success: false, error: 'Response too short (' + html.length + ' chars)' };
        }

        // Check for bot detection
        if (html.indexOf('blocked') !== -1 && html.indexOf('automated') !== -1) {
            return { success: false, error: 'DuckDuckGo bot detection triggered' };
        }

        console.log('[DDG] ✅ Response received (' + html.length + ' chars)');
        return { success: true, html: html };
    }

    /**
     * Search with retry.
     *
     * @param {string} query
     * @param {string} [proxyUrl]
     * @param {object} [fp]
     * @param {number} [maxRetries=2]
     * @returns {{ success: boolean, html?: string, error?: string }}
     */
    static async searchWithRetry(query, proxyUrl, fp, maxRetries) {
        maxRetries = maxRetries || 2;
        var lastError = '';

        for (var attempt = 0; attempt <= maxRetries; attempt++) {
            if (attempt > 0) {
                console.log('[DDG] Retry ' + attempt + '/' + maxRetries + '...');
                await new Promise(function (resolve) { setTimeout(resolve, 800 * attempt); });
            }

            var result = await SearchService.search(query, proxyUrl, fp);
            if (result.success) return result;

            lastError = result.error || 'Unknown error';
            console.warn('[DDG] Attempt ' + (attempt + 1) + ' failed: ' + lastError);
        }

        return { success: false, error: 'All attempts failed. Last: ' + lastError };
    }
}

module.exports = SearchService;
