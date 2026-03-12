// scripts/chatgpt/controllers/chat.js
// Controller for POST /v1/chat/completions endpoint
// Supports text-only chat, mixed text+image, AND function calling (tool calling)

const ChatGPT = require('../api/chatgpt.js');
const Helpers = require('../core/helpers.js');
const ApiError = require('../errors/api-error.js');
const FunctionCalling = require('../services/function-calling.js');

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
     * Extracts tools array for function calling support.
     *
     * @param {object} req
     * @returns {{ validMessages: Array, model: string, totalContentLength: number,
     *             hasImage: boolean, imageMessageIndex: number, imageInput: string,
     *             tools: Array|null, toolChoice: string|object|null }}
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
        var tools = body.tools || null;
        var toolChoice = body.tool_choice || null;

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

            // Handle tool-role messages (function calling results)
            if (msg.role === 'tool') {
                validMessages.push({
                    role: 'tool',
                    content: msg.content || '{}',
                    tool_call_id: msg.tool_call_id || ''
                });
                totalContentLength += (msg.content || '').length;
                continue;
            }

            // Handle assistant messages with tool_calls
            if (msg.role === 'assistant' && msg.tool_calls) {
                validMessages.push({
                    role: 'assistant',
                    content: msg.content || '',
                    tool_calls: msg.tool_calls
                });
                totalContentLength += (msg.content || '').length;
                continue;
            }

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
            imageInput: imageInput,
            tools: tools,
            toolChoice: toolChoice
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
     * Supports text-only, mixed text+image, and function calling (tool calling).
     * @throws {ApiError}
     */
    async chatCompletions(req, res) {
        var s = this.stats;
        s.requestCount++;

        // ── Validate ──
        var parsed = this.parseRequest(req);

        // ── Call API ──
        var result;
        var hasTools = parsed.tools && Array.isArray(parsed.tools) && parsed.tools.length > 0;

        if (parsed.hasImage) {
            // Image + text (tools not supported with images)
            console.log('[ChatGPT] Request: model=' + parsed.model + ', messages=' + parsed.validMessages.length + ', has_image=true');
            result = await ChatGPT.askWithImage(
                parsed.validMessages,
                parsed.imageInput,
                parsed.imageMessageIndex,
                parsed.model
            );
        } else if (hasTools) {
            // Function calling / tool calling
            console.log('[ChatGPT] Request: model=' + parsed.model + ', messages=' + parsed.validMessages.length + ', tools=' + parsed.tools.length);
            result = await ChatGPT.askWithTools(parsed.validMessages, parsed.model, parsed.tools);
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

        // Check if result contains tool calls
        if (result.hasToolCalls && result.toolCalls) {
            var toolResponse = FunctionCalling.formatToolCallsResponse(
                result.toolCalls, result.model, inputTokens, outputTokens
            );
            res.json(toolResponse);
            console.log('[ChatGPT] ✅ Tool calls response sent (' + result.toolCalls.length + ' calls)');
        } else {
            res.json(this.formatResponse(result, inputTokens, outputTokens));
            console.log('[ChatGPT] ✅ Response sent (' + (result.response || '').length + ' chars)');
        }
    }
}

module.exports = ChatController;
