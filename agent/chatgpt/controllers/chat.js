// scripts/chatgpt/controllers/chat.js
// Controller for POST /v1/chat/completions endpoint
// Supports text-only chat and mixed text+image

const ChatGPT = require('../api/chatgpt.js');
const Helpers = require('../core/helpers.js');
const ApiError = require('../errors/api-error.js');

class ChatController {
    /**
     * @param {object} stats — shared stats counters reference
     */
    constructor(stats) {
        this.stats = stats;
    }

    /**
     * Parse and validate the request body.
     * Preserves image_url on messages for mixed text+image support.
     *
     * @param {object} req
     * @returns {{ validMessages: Array, model: string, totalContentLength: number,
     *             hasImage: boolean, imageMessageIndex: number, imageInput: string }}
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
        var model = body.model || 'gpt-4o-mini';

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            throw ApiError.badRequest('messages array is required');
        }

        var validMessages = [];
        var totalContentLength = 0;
        var hasImage = false;
        var imageMessageIndex = -1;
        var imageInput = '';

        for (var i = 0; i < messages.length; i++) {
            var msg = messages[i];

            if (msg.role && msg.content) {
                var entry = { role: msg.role, content: msg.content };

                // Check for image attachment
                var imgUrl = msg.image_url || msg.image || msg.image_data;
                if (imgUrl && !hasImage) {
                    hasImage = true;
                    imageMessageIndex = validMessages.length; // Index in validMessages
                    imageInput = imgUrl;
                    entry.image_url = imgUrl;
                }

                validMessages.push(entry);
                totalContentLength += msg.content.length;
            }
        }

        if (validMessages.length === 0) {
            throw ApiError.badRequest('No content found in messages');
        }

        return {
            validMessages: validMessages,
            model: model,
            totalContentLength: totalContentLength,
            hasImage: hasImage,
            imageMessageIndex: imageMessageIndex,
            imageInput: imageInput
        };
    }

    /**
     * Format the successful ChatGPT result into OpenAI-compatible response.
     */
    formatResponse(result, inputTokens, outputTokens) {
        var completionId = 'chatcmpl-' + Helpers.generateUUID().replace(/-/g, '').substring(0, 24);
        return {
            id: completionId,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: result.model,
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
     * Supports text-only and mixed text+image.
     * @throws {ApiError}
     */
    async chatCompletions(req, res) {
        var s = this.stats;
        s.requestCount++;

        // ── Validate ──
        var parsed = this.parseRequest(req);

        // ── Call API ──
        var result;

        if (parsed.hasImage) {
            // Image + text
            console.log('[ChatGPT] Request: model=' + parsed.model + ', messages=' + parsed.validMessages.length + ', has_image=true');
            result = await ChatGPT.askWithImage(
                parsed.validMessages,
                parsed.imageInput,
                parsed.imageMessageIndex,
                parsed.model
            );
        } else {
            // Text-only
            console.log('[ChatGPT] Request: model=' + parsed.model + ', messages=' + parsed.validMessages.length + ', total_length=' + parsed.totalContentLength);
            result = await ChatGPT.ask(parsed.validMessages, parsed.model);
        }

        if (!result.success) {
            s.failureCount++;
            throw ApiError.upstream(result.error || 'ChatGPT request failed');
        }

        // ── Build response ──
        var inputTokens = Math.ceil(parsed.totalContentLength / 4);
        var outputTokens = Math.ceil((result.response || '').length / 4);

        s.successCount++;
        s.totalInputTokens += inputTokens;
        s.totalOutputTokens += outputTokens;

        res.json(this.formatResponse(result, inputTokens, outputTokens));
        console.log('[ChatGPT] ✅ Response sent (' + (result.response || '').length + ' chars)');
    }
}

module.exports = ChatController;
