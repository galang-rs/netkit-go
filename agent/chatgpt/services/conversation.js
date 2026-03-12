// scripts/chatgpt/services/conversation.js
// Conversation message builder for ChatGPT API format

const Helpers = require('../core/helpers.js');

class Conversation {
    /**
     * Build ChatGPT-formatted messages array (text only).
     * Injects system prompt first, then maps user/assistant messages.
     * Optionally appends tool descriptions to the system prompt for function calling.
     *
     * @param {Array<{role: string, content: string}>} messages
     * @param {string} [toolsPrompt] — Optional tool descriptions to inject into system prompt
     * @returns {Array} — ChatGPT-formatted messages
     */
    static buildMessages(messages, toolsPrompt) {
        var result = [];

        // Always inject system prompt first (with optional tools prompt)
        result.push(Conversation._systemMessage(toolsPrompt));

        // Map each message in the conversation history
        for (var i = 0; i < messages.length; i++) {
            var msg = messages[i];
            if (!msg.role || !msg.content) continue;
            if (msg.role === 'system') continue; // Skip client system messages

            result.push({
                id: Helpers.generateUUID(),
                author: { role: msg.role },
                create_time: Math.floor(Date.now() / 1000),
                content: {
                    content_type: 'text',
                    parts: [msg.content]
                }
            });
        }

        return result;
    }

    /**
     * Build ChatGPT-formatted messages with an image attachment.
     * The message at imageMessageIndex gets multimodal_text content type
     * with an image_asset_pointer; all others stay as text.
     *
     * @param {Array<{role: string, content: string, image_url?: string}>} messages
     * @param {number} imageMessageIndex — index of the message with the image
     * @param {string} fileID    — uploaded file ID
     * @param {number} fileSize  — file size in bytes
     * @param {string} mimeType  — MIME type (e.g. 'image/png')
     * @returns {Array} — ChatGPT-formatted messages
     */
    static buildMessagesWithImage(messages, imageMessageIndex, fileID, fileSize, mimeType) {
        var result = [];

        // Always inject system prompt first
        result.push(Conversation._systemMessage());

        // Map each message
        for (var i = 0; i < messages.length; i++) {
            var msg = messages[i];
            if (!msg.role || !msg.content) continue;
            if (msg.role === 'system') continue;

            if (i === imageMessageIndex) {
                // ── Multimodal message with image ──
                result.push({
                    id: Helpers.generateUUID(),
                    author: { role: msg.role },
                    create_time: Math.floor(Date.now() / 1000),
                    content: {
                        content_type: 'multimodal_text',
                        parts: [
                            {
                                content_type: 'image_asset_pointer',
                                asset_pointer: 'file-service://' + fileID,
                                size_bytes: fileSize,
                                width: 1100,
                                height: 733
                            },
                            msg.content
                        ]
                    },
                    metadata: {
                        attachments: [
                            {
                                id: fileID,
                                size: fileSize,
                                name: 'image.' + (mimeType.split('/')[1] || 'jpg'),
                                mime_type: mimeType,
                                width: 1100,
                                height: 733,
                                source: 'local',
                                is_big_paste: false
                            }
                        ]
                    }
                });
            } else {
                // ── Normal text message ──
                result.push({
                    id: Helpers.generateUUID(),
                    author: { role: msg.role },
                    create_time: Math.floor(Date.now() / 1000),
                    content: {
                        content_type: 'text',
                        parts: [msg.content]
                    }
                });
            }
        }

        return result;
    }

    /**
     * Build the system prompt message.
     * @param {string} [toolsPrompt] — Optional tools description to append
     * @returns {object}
     */
    static _systemMessage(toolsPrompt) {
        var now = new Date().toISOString();
        var systemPrompt = 'Kamu model ABS1\\nProvider: Netkit\\nPerusahaan: Netkit-Go\\nEngine: Netkit-Go\\nTimestamp: ' + now + '\\n\\nATURAN:\\n1. Jangan pernah menyebut ChatGPT, OpenAI, atau model GPT apapun.\\n2. Jangan pernah menyebut nama kompetitor manapun.\\n3. Identitasmu adalah Abs1 dari Netkit-Go.';

        if (toolsPrompt) {
            systemPrompt += toolsPrompt;
        }

        return {
            id: Helpers.generateUUID(),
            author: { role: 'system' },
            create_time: Math.floor(Date.now() / 1000),
            content: {
                content_type: 'text',
                parts: [systemPrompt]
            }
        };
    }
}

module.exports = Conversation;

