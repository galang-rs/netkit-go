// agent/duckduckgo/controllers/search.js
// Controller for POST /v1/chat/completions — DuckDuckGo Search endpoint
// Accepts OpenAI-compatible request format, extracts query, returns AI overview

const DuckDuckGo = require('../api/duckduckgo.js');
const Helpers = require('../core/helpers.js');
const ApiError = require('../errors/api-error.js');

class SearchController {
    /**
     * @param {object} stats — shared stats counters reference
     */
    constructor(stats) {
        this.stats = stats;
    }

    /**
     * Parse and validate the OpenAI-format request body.
     * Extracts the last user message as the search query.
     *
     * @param {object} req
     * @returns {{ query: string, model: string, useProxy: boolean }}
     * @throws {ApiError}
     */
    parseRequest(req) {
        var body;
        try {
            body = JSON.parse(req.bodyString || '{}');
        } catch (e) {
            throw ApiError.invalidJSON();
        }

        var messages = body.messages;
        var model = body.model || 'duckduckgo-search';

        // Support direct query string
        if (body.query && typeof body.query === 'string') {
            return {
                query: body.query,
                model: model,
                useProxy: body.use_proxy !== false
            };
        }

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            throw ApiError.badRequest('messages array is required');
        }

        // Extract the last user message as the search query
        var query = '';
        for (var i = messages.length - 1; i >= 0; i--) {
            if (messages[i].role === 'user' && messages[i].content) {
                query = messages[i].content;
                break;
            }
        }

        if (!query) {
            throw ApiError.badRequest('No user message found in messages');
        }

        return {
            query: query,
            model: model,
            useProxy: body.use_proxy !== false
        };
    }

    /**
     * Format the result into OpenAI-compatible response.
     */
    formatResponse(result, query) {
        var completionId = 'chatcmpl-' + Helpers.generateUUID().replace(/-/g, '').substring(0, 24);
        var inputTokens = Math.ceil(query.length / 4);
        var outputTokens = Math.ceil((result.response || '').length / 4);

        return {
            id: completionId,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: result.model || 'duckduckgo-search',
            choices: [
                {
                    index: 0,
                    message: {
                        role: 'assistant',
                        content: result.response
                    },
                    finish_reason: 'stop'
                }
            ],
            usage: {
                prompt_tokens: inputTokens,
                completion_tokens: outputTokens,
                total_tokens: inputTokens + outputTokens
            }
        };
    }

    /**
     * POST /v1/chat/completions — main handler
     * Accepts OpenAI-format messages, extracts last user message as search query.
     * @throws {ApiError}
     */
    async chatCompletions(req, res) {
        var s = this.stats;
        s.requestCount++;

        // ── Validate ──
        var parsed = this.parseRequest(req);
        console.log('[DuckDuckGo] Request: query="' + parsed.query.substring(0, 50) + '", proxy=' + parsed.useProxy);

        // ── Call API ──
        var result;
        if (parsed.useProxy) {
            result = await DuckDuckGo.search(parsed.query);
        } else {
            result = await DuckDuckGo.searchDirect(parsed.query);
        }

        if (!result.success) {
            s.failureCount++;
            throw ApiError.upstream(result.error || 'DuckDuckGo Search failed');
        }

        // ── Build response ──
        var inputTokens = Math.ceil(parsed.query.length / 4);
        var outputTokens = Math.ceil((result.response || '').length / 4);

        s.successCount++;
        s.totalInputTokens += inputTokens;
        s.totalOutputTokens += outputTokens;

        res.json(this.formatResponse(result, parsed.query));
        console.log('[DuckDuckGo] ✅ Response sent (' + (result.response || '').length + ' chars)');
    }
}

module.exports = SearchController;
