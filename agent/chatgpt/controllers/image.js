// scripts/chatgpt/controllers/image.js
// Controller for POST /v1/images/analyze endpoint
// Returns OpenAI chat completions format (same as /v1/chat/completions)

const ChatGPT = require('../api/chatgpt.js');
const Helpers = require('../core/helpers.js');
const ApiError = require('../errors/api-error.js');

class ImageController {
    /**
     * @param {object} stats — shared stats counters reference
     */
    constructor(stats) {
        this.stats = stats;
    }

    /**
     * Parse and validate the image analysis request.
     * @param {object} req
     * @returns {{ imageInput: string, prompt: string }}
     * @throws {ApiError}
     */
    parseRequest(req) {
        var body;
        try {
            body = JSON.parse(req.bodyString || '{}');
        } catch (e) {
            throw ApiError.invalidJSON();
        }

        var imageInput = body.image_url || body.image || body.image_data;
        var prompt = body.prompt || 'Describe this image in detail';

        if (!imageInput) {
            throw ApiError.missingField('image_url (URL, base64, hex, or data URI)');
        }

        return { imageInput: imageInput, prompt: prompt };
    }

    /**
     * POST /v1/images/analyze — main handler
     * Returns chat completions format for consistency.
     * @throws {ApiError}
     */
    async imageAnalyze(req, res) {
        var s = this.stats;
        s.requestCount++;

        // ── Validate ──
        var parsed = this.parseRequest(req);
        console.log('[Image] Request: prompt=' + parsed.prompt.substring(0, 50) + (parsed.prompt.length > 50 ? '...' : ''));

        // ── Call API ──
        var result = await ChatGPT.analyzeImage(parsed.imageInput, parsed.prompt);

        if (!result.success) {
            s.failureCount++;
            throw ApiError.upstream(result.error || 'Image analysis request failed');
        }

        // ── Build chat completions response ──
        var outputTokens = Math.ceil((result.response || '').length / 4);
        s.successCount++;
        s.totalOutputTokens += outputTokens;

        var completionId = 'chatcmpl-' + Helpers.generateUUID().replace(/-/g, '').substring(0, 24);

        res.json({
            id: completionId,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: 'auto',
            choices: [
                {
                    index: 0,
                    message: {
                        role: 'assistant',
                        content: result.response || result.description
                    },
                    finish_reason: 'stop'
                }
            ],
            usage: {
                prompt_tokens: 0,
                completion_tokens: outputTokens,
                total_tokens: outputTokens
            }
        });

        console.log('[Image] ✅ Analysis sent (' + (result.response || '').length + ' chars)');
    }
}

module.exports = ImageController;


