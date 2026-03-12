// scripts/chatgpt/services/function-calling.js
// Function calling (tool calling) service
// Handles prompt injection for tools and parsing model responses for tool calls

const Helpers = require('../core/helpers.js');

class FunctionCalling {
    /**
     * Build a system prompt section that describes available tools to the model.
     * Instructs the model to respond with a specific JSON format when it needs
     * to call a function.
     *
     * @param {Array} tools — OpenAI-format tools array
     * @returns {string} — Prompt text to inject into system message
     */
    static buildToolPrompt(tools) {
        if (!tools || !Array.isArray(tools) || tools.length === 0) return '';

        var functionDescriptions = [];
        for (var i = 0; i < tools.length; i++) {
            var tool = tools[i];
            if (tool.type !== 'function' || !tool.function) continue;

            var fn = tool.function;
            var desc = '### ' + fn.name + '\n';
            if (fn.description) desc += fn.description + '\n';
            if (fn.parameters) {
                desc += 'Parameters (JSON Schema):\n```json\n' + JSON.stringify(fn.parameters, null, 2) + '\n```';
            }
            functionDescriptions.push(desc);
        }

        if (functionDescriptions.length === 0) return '';

        return '\n\n---\n' +
            'You have access to the following tools/functions. ' +
            'When you need to use a tool, you MUST respond with ONLY a JSON block in this exact format (no other text before or after):\n\n' +
            '```json\n' +
            '{"tool_calls": [{"name": "function_name", "arguments": {"param": "value"}}]}\n' +
            '```\n\n' +
            'If you need to call multiple functions, include them all in the tool_calls array.\n' +
            'If you do NOT need to call any function, respond normally with text.\n\n' +
            '## Available Functions:\n\n' +
            functionDescriptions.join('\n\n');
    }

    /**
     * Parse model response text to detect function/tool calls.
     * Looks for JSON blocks matching the tool_calls format.
     *
     * @param {string} responseText — Full model response text
     * @returns {{ hasToolCalls: boolean, toolCalls: Array, textContent: string }}
     */
    static parseToolCalls(responseText) {
        if (!responseText || typeof responseText !== 'string') {
            return { hasToolCalls: false, toolCalls: [], textContent: responseText || '' };
        }

        var text = responseText.trim();

        // ── Strategy 1: Try parsing the entire response as JSON ──
        var parsed = FunctionCalling._tryParseToolCallsJSON(text);
        if (parsed) return parsed;

        // ── Strategy 2: Extract JSON from markdown code block ──
        var codeBlockMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/);
        if (codeBlockMatch) {
            parsed = FunctionCalling._tryParseToolCallsJSON(codeBlockMatch[1].trim());
            if (parsed) return parsed;
        }

        // ── Strategy 3: Find JSON object with tool_calls key anywhere ──
        var jsonMatch = text.match(/\{[\s\S]*"tool_calls"[\s\S]*\}/);
        if (jsonMatch) {
            parsed = FunctionCalling._tryParseToolCallsJSON(jsonMatch[0].trim());
            if (parsed) return parsed;
        }

        // No tool calls detected — return as normal text
        return { hasToolCalls: false, toolCalls: [], textContent: text };
    }

    /**
     * Try to parse a string as a tool_calls JSON response.
     * @param {string} str
     * @returns {{ hasToolCalls: boolean, toolCalls: Array, textContent: string }|null}
     */
    static _tryParseToolCallsJSON(str) {
        try {
            var obj = JSON.parse(str);
            if (obj && Array.isArray(obj.tool_calls) && obj.tool_calls.length > 0) {
                var toolCalls = [];
                for (var i = 0; i < obj.tool_calls.length; i++) {
                    var tc = obj.tool_calls[i];
                    if (tc.name) {
                        toolCalls.push({
                            id: 'call_' + Helpers.generateUUID().replace(/-/g, '').substring(0, 24),
                            type: 'function',
                            function: {
                                name: tc.name,
                                arguments: typeof tc.arguments === 'string'
                                    ? tc.arguments
                                    : JSON.stringify(tc.arguments || {})
                            }
                        });
                    }
                }
                if (toolCalls.length > 0) {
                    return { hasToolCalls: true, toolCalls: toolCalls, textContent: '' };
                }
            }
        } catch (e) {
            // Not valid JSON
        }
        return null;
    }

    /**
     * Convert tool role messages to user-role messages the model can understand.
     * ChatGPT backend-anon doesn't have a native "tool" role, so we format
     * tool results as user messages.
     *
     * Also converts assistant messages with tool_calls into text representations.
     *
     * @param {Array} messages — messages array that may contain tool role messages
     * @returns {Array} — cleaned messages with tool roles converted
     */
    static convertToolMessages(messages) {
        var result = [];
        for (var i = 0; i < messages.length; i++) {
            var msg = messages[i];

            if (msg.role === 'tool') {
                // Convert tool result to user message
                var toolContent = 'Function result';
                if (msg.tool_call_id) {
                    toolContent += ' (call_id: ' + msg.tool_call_id + ')';
                }
                toolContent += ':\n' + (msg.content || '{}');

                result.push({
                    role: 'user',
                    content: toolContent
                });
            } else if (msg.role === 'assistant' && msg.tool_calls && Array.isArray(msg.tool_calls)) {
                // Convert assistant tool_calls message to text
                var callsText = 'I need to call the following functions:\n';
                for (var j = 0; j < msg.tool_calls.length; j++) {
                    var tc = msg.tool_calls[j];
                    callsText += '- ' + (tc.function ? tc.function.name : 'unknown');
                    if (tc.function && tc.function.arguments) {
                        callsText += '(' + tc.function.arguments + ')';
                    }
                    if (tc.id) {
                        callsText += ' [call_id: ' + tc.id + ']';
                    }
                    callsText += '\n';
                }
                result.push({
                    role: 'assistant',
                    content: callsText.trim()
                });
            } else {
                result.push(msg);
            }
        }
        return result;
    }

    /**
     * Format detected tool calls into an OpenAI-compatible chat completion response.
     *
     * @param {Array} toolCalls — Array of { id, type, function: { name, arguments } }
     * @param {string} model
     * @param {number} inputTokens
     * @param {number} outputTokens
     * @returns {object} — OpenAI-compatible response with tool_calls
     */
    static formatToolCallsResponse(toolCalls, model, inputTokens, outputTokens) {
        var completionId = 'chatcmpl-' + Helpers.generateUUID().replace(/-/g, '').substring(0, 24);
        return {
            id: completionId,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: model,
            choices: [
                {
                    index: 0,
                    message: {
                        role: 'assistant',
                        content: null,
                        tool_calls: toolCalls
                    },
                    finish_reason: 'tool_calls'
                }
            ],
            usage: {
                prompt_tokens: inputTokens,
                completion_tokens: outputTokens,
                total_tokens: inputTokens + outputTokens
            }
        };
    }
}

module.exports = FunctionCalling;
