// agent/duckduckgo/api/duckduckgo.js
// Public API — Search entry point using DuckDuckGo
// Flow: WARP proxy → DuckDuckGo HTML → parse → clean markdown text

const Warp = require('../../chatgpt/proxy/warp.js');
const SearchService = require('../services/search.js');
const HtmlParser = require('../core/html-parser.js');

class DuckDuckGo {
    /**
     * Search DuckDuckGo and return clean text results.
     * Uses WARP proxy for IP rotation.
     *
     * @param {string} query — Search query
     * @param {string} [lang='en']
     * @returns {{ success: boolean, response?: string, error?: string, model: string }}
     */
    static async search(query, lang) {
        return await Warp.withProxy(async function (proxyUrl, snapshot) {
            try {
                console.log('[Search] Searching: "' + query.substring(0, 60) + '"...');

                var searchResult = await SearchService.searchWithRetry(query, proxyUrl, null, 2);
                if (!searchResult.success) {
                    return { success: false, error: searchResult.error, model: 'duckduckgo-search' };
                }

                var parsed = HtmlParser.extractSearchResults(searchResult.html);
                if (parsed.found && parsed.text && parsed.text.length > 30) {
                    console.log('[Search] ✅ Results extracted (' + parsed.text.length + ' chars)');
                    return { success: true, response: parsed.text, model: 'duckduckgo-search' };
                }

                return {
                    success: false,
                    error: 'Could not extract results from DuckDuckGo response.',
                    model: 'duckduckgo-search'
                };
            } catch (err) {
                console.error('[Search] Error:', err);
                return { success: false, error: String(err), model: 'duckduckgo-search' };
            }
        });
    }

    /**
     * Search without WARP proxy (direct connection).
     */
    static async searchDirect(query, lang) {
        try {
            console.log('[Search] Direct search: "' + query.substring(0, 60) + '"...');

            var searchResult = await SearchService.searchWithRetry(query, null, null, 1);
            if (!searchResult.success) {
                return { success: false, error: searchResult.error, model: 'duckduckgo-search' };
            }

            var parsed = HtmlParser.extractSearchResults(searchResult.html);
            if (parsed.found && parsed.text && parsed.text.length > 30) {
                console.log('[Search] ✅ Direct results (' + parsed.text.length + ' chars)');
                return { success: true, response: parsed.text, model: 'duckduckgo-search' };
            }

            return {
                success: false,
                error: 'Could not extract results.',
                model: 'duckduckgo-search'
            };
        } catch (err) {
            console.error('[Search] Direct error:', err);
            return { success: false, error: String(err), model: 'duckduckgo-search' };
        }
    }
}

module.exports = DuckDuckGo;
