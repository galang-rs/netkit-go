// scripts/chatgpt/api/chatgpt.js
// Public API — ChatGPT.ask() and ChatGPT.analyzeImage() entry points
// Flow: WARP init (snapshot) → Sentinel auth (with snapshot) → conversation → SSE parse

const Helpers = require('../core/helpers.js');
const Warp = require('../proxy/warp.js');
const Sentinel = require('../auth/sentinel.js');
const Headers = require('../network/headers.js');
const SSEParser = require('../services/sse-parser.js');
const Conversation = require('../services/conversation.js');
const FileUpload = require('../services/file-upload.js');
const FunctionCalling = require('../services/function-calling.js');

class ChatGPT {
    /**
     * Ask ChatGPT using the free translate endpoint exploit.
     * Supports single prompt string or multi-turn messages array.
     *
     * Flow:
     *   1. WARP register → captures initial fingerprint snapshot
     *   2. Sentinel auth → uses WARP snapshot for TLS continuity
     *   3. Conversation request → uses auth fingerprint
     *   4. SSE parse → extracts response text
     *
     * @param {string|Array<{role: string, content: string}>} promptOrMessages
     * @param {string} [model='gpt-4o-mini']
     * @returns {{ success: boolean, response?: string, error?: string, model: string }}
     */
    static async ask(promptOrMessages, model) {
        model = model || 'gpt-4o-mini';

        // Normalize input
        var messages;
        if (typeof promptOrMessages === 'string') {
            messages = [{ role: 'user', content: promptOrMessages }];
        } else if (Array.isArray(promptOrMessages)) {
            messages = promptOrMessages;
        } else {
            return { success: false, error: 'Invalid input: expected string or messages array', model: model };
        }

        // WARP provides both proxyUrl AND initial fingerprint snapshot
        return await Warp.withProxy(async function (proxyUrl, snapshot) {
            try {
                // ── Authenticate via sentinel — pass WARP snapshot ──
                var auth = await Sentinel.authenticate(proxyUrl, snapshot);

                // ── Build conversation messages & send request ──
                var conversationMessages = Conversation.buildMessages(messages);
                console.log('[ChatGPT] Sending conversation request (model: ' + model + ', messages: ' + conversationMessages.length + ')...');

                var conversationBody = JSON.stringify({
                    action: 'next',
                    conversation_mode: { kind: 'primary_assistant' },
                    history_and_training_disabled: true,
                    is_visible: true,
                    messages: conversationMessages,
                    model: model,
                    supported_encodings: [],
                    supports_buffering: false
                });

                var req = await fetch('https://chatgpt.com/backend-anon/conversation', {
                    method: 'POST',
                    fingerprint: auth.fp,
                    agent: proxyUrl,
                    headers: Headers.build(auth.config, auth.deviceId, auth.oaiBuildId, {
                        'openai-sentinel-chat-requirements-token': auth.token,
                        'openai-sentinel-proof-token': auth.powAnswer || '',
                        'openai-sentinel-turnstile-token': auth.powAnswer || '',
                        'Accept': 'text/event-stream'
                    }),
                    body: conversationBody
                });

                if (!req.ok) {
                    return { success: false, error: 'Conversation request failed: HTTP ' + req.status + ' — ' + (req.body || '').substring(0, 200), model: model };
                }

                // ── Parse SSE response ──
                var parsed = SSEParser.parse(req.body || '');

                if (!parsed.text && parsed.dataLineCount === 0) {
                    return { success: false, error: 'No data lines in response: ' + parsed.raw, model: model };
                }

                if (!parsed.text) {
                    return { success: false, error: 'Could not extract text from ' + parsed.dataLineCount + ' SSE events. Raw: ' + parsed.raw, model: model };
                }

                console.log('[ChatGPT] ✅ Response received (' + parsed.text.length + ' chars)');
                return { success: true, response: parsed.text, model: model };

            } catch (err) {
                console.error('[ChatGPT] Error:', err);
                return { success: false, error: String(err), model: model };
            }
        });
    }

    /**
     * Ask ChatGPT with function/tool calling support.
     * Tools are injected into the system prompt. The response is parsed
     * to detect tool calls. If detected, returns tool_calls; otherwise
     * returns normal text response.
     *
     * @param {Array<{role: string, content: string}>} messages
     * @param {string} [model='gpt-4o-mini']
     * @param {Array} tools — OpenAI-format tools array
     * @returns {{ success: boolean, response?: string, toolCalls?: Array, hasToolCalls?: boolean, error?: string, model: string }}
     */
    static async askWithTools(messages, model, tools) {
        model = model || 'gpt-4o-mini';

        // Build tool prompt from tools definitions
        var toolsPrompt = FunctionCalling.buildToolPrompt(tools);

        // Convert any tool-role messages to user-role messages
        var convertedMessages = FunctionCalling.convertToolMessages(messages);

        return await Warp.withProxy(async function (proxyUrl, snapshot) {
            try {
                // ── Authenticate via sentinel ──
                var auth = await Sentinel.authenticate(proxyUrl, snapshot);

                // ── Build conversation messages with tools prompt injected ──
                var conversationMessages = Conversation.buildMessages(convertedMessages, toolsPrompt);
                console.log('[ChatGPT] Sending tool-calling request (model: ' + model + ', messages: ' + conversationMessages.length + ', tools: ' + tools.length + ')...');

                var conversationBody = JSON.stringify({
                    action: 'next',
                    conversation_mode: { kind: 'primary_assistant' },
                    history_and_training_disabled: true,
                    is_visible: true,
                    messages: conversationMessages,
                    model: model,
                    supported_encodings: [],
                    supports_buffering: false
                });

                var req = await fetch('https://chatgpt.com/backend-anon/conversation', {
                    method: 'POST',
                    fingerprint: auth.fp,
                    agent: proxyUrl,
                    headers: Headers.build(auth.config, auth.deviceId, auth.oaiBuildId, {
                        'openai-sentinel-chat-requirements-token': auth.token,
                        'openai-sentinel-proof-token': auth.powAnswer || '',
                        'openai-sentinel-turnstile-token': auth.powAnswer || '',
                        'Accept': 'text/event-stream'
                    }),
                    body: conversationBody
                });

                if (!req.ok) {
                    return { success: false, error: 'Tool-calling request failed: HTTP ' + req.status + ' — ' + (req.body || '').substring(0, 200), model: model };
                }

                // ── Parse SSE response ──
                var parsed = SSEParser.parse(req.body || '');

                if (!parsed.text && parsed.dataLineCount === 0) {
                    return { success: false, error: 'No data lines in response: ' + parsed.raw, model: model };
                }
                if (!parsed.text) {
                    return { success: false, error: 'Could not extract text from ' + parsed.dataLineCount + ' SSE events. Raw: ' + parsed.raw, model: model };
                }

                // ── Check for tool calls in response ──
                var toolResult = FunctionCalling.parseToolCalls(parsed.text);
                if (toolResult.hasToolCalls) {
                    console.log('[ChatGPT] ✅ Tool calls detected (' + toolResult.toolCalls.length + ' calls)');
                    return {
                        success: true,
                        hasToolCalls: true,
                        toolCalls: toolResult.toolCalls,
                        response: '',
                        model: model
                    };
                }

                console.log('[ChatGPT] ✅ Text response received (' + parsed.text.length + ' chars, no tool calls)');
                return { success: true, hasToolCalls: false, response: parsed.text, model: model };

            } catch (err) {
                console.error('[ChatGPT] Tool-calling error:', err);
                return { success: false, error: String(err), model: model };
            }
        });
    }

    /**
     * Ask ChatGPT with an image attachment in a multi-turn conversation.
     * Messages can include text-only and one image message. The image is
     * uploaded first, then a multimodal conversation is sent.
     *
     * Flow:
     *   1. WARP register → fresh IP + snapshot
     *   2. Sentinel auth → tokens
     *   3. Decode + upload image (initiate → PUT → process)
     *   4. Build messages: text messages + one multimodal_text with image
     *   5. Send conversation → SSE parse
     *
     * @param {Array<{role: string, content: string, image_url?: string}>} messages
     * @param {string} imageInput         — Image data (base64, hex, data URI, or URL)
     * @param {number} imageMessageIndex  — Index of the message with the image
     * @param {string} [model='auto']
     * @returns {{ success: boolean, response?: string, error?: string, model: string }}
     */
    static async askWithImage(messages, imageInput, imageMessageIndex, model) {
        model = model || 'auto';

        return await Warp.withProxy(async function (proxyUrl, snapshot) {
            try {
                // ── Step 1: Authenticate via sentinel ──
                console.log('[ChatGPT] Starting image+chat flow...');
                var auth = await Sentinel.authenticate(proxyUrl, snapshot);

                // ── Step 2: Decode image input ──
                console.log('[ChatGPT] Decoding image input...');
                var decoded = await Helpers.decodeImageInput(imageInput, proxyUrl, auth.fp);
                console.log('[ChatGPT] Image decoded: ' + decoded.fileName + ' (' + decoded.data.length + ' bytes, ' + decoded.mimeType + ')');

                var baseHeaders = Headers.build(auth.config, auth.deviceId, auth.oaiBuildId);

                // ── Step 3: Upload image ──
                var uploadResult = await FileUpload.initiateUpload(
                    proxyUrl, auth.fp, baseHeaders,
                    decoded.fileName, decoded.data.length
                );

                await FileUpload.uploadFile(
                    uploadResult.upload_url,
                    decoded.data,
                    decoded.mimeType
                );

                var processedFp = await FileUpload.processUpload(
                    proxyUrl, uploadResult.fp || auth.fp, baseHeaders,
                    uploadResult.file_id, decoded.fileName
                );

                // ── Step 4: Build multimodal conversation messages ──
                var conversationMessages = Conversation.buildMessagesWithImage(
                    messages, imageMessageIndex,
                    uploadResult.file_id, decoded.data.length, decoded.mimeType
                );
                console.log('[ChatGPT] Sending conversation request (model: ' + model + ', messages: ' + conversationMessages.length + ', has_image: true)...');

                var conversationBody = JSON.stringify({
                    action: 'next',
                    conversation_mode: { kind: 'primary_assistant' },
                    history_and_training_disabled: true,
                    is_visible: true,
                    messages: conversationMessages,
                    model: model,
                    supported_encodings: [],
                    supports_buffering: false
                });

                // ── Step 5: Send conversation request ──
                var req = await fetch('https://chatgpt.com/backend-anon/conversation', {
                    method: 'POST',
                    fingerprint: processedFp || auth.fp,
                    agent: proxyUrl,
                    headers: Headers.build(auth.config, auth.deviceId, auth.oaiBuildId, {
                        'openai-sentinel-chat-requirements-token': auth.token,
                        'openai-sentinel-proof-token': auth.powAnswer || '',
                        'openai-sentinel-turnstile-token': auth.powAnswer || '',
                        'Accept': 'text/event-stream',
                        'X-Custom-Timeout': '120'
                    }),
                    body: conversationBody
                });

                if (!req.ok) {
                    return { success: false, error: 'Image conversation failed: HTTP ' + req.status + ' — ' + (req.body || '').substring(0, 200), model: model };
                }

                // ── Step 6: Parse SSE response ──
                var parsed = SSEParser.parse(req.body || '');

                if (!parsed.text && parsed.dataLineCount === 0) {
                    return { success: false, error: 'No data lines in response: ' + parsed.raw, model: model };
                }
                if (!parsed.text) {
                    return { success: false, error: 'Could not extract text from ' + parsed.dataLineCount + ' SSE events. Raw: ' + parsed.raw, model: model };
                }

                console.log('[ChatGPT] ✅ Image+chat response received (' + parsed.text.length + ' chars)');
                return { success: true, response: parsed.text, model: model };

            } catch (err) {
                console.error('[ChatGPT] Image+chat error:', err);
                return { success: false, error: String(err), model: model };
            }
        });
    }

    /**
     * Analyze an image by uploading it to ChatGPT and sending a multimodal message.
     *
     * Flow:
     *   1. WARP register → fresh IP + snapshot
     *   2. Sentinel auth → tokens
     *   3. Decode image input (base64/hex/URL/data URI)
     *   4. File upload: initiate → PUT to Azure → process
     *   5. Send multimodal conversation with image_asset_pointer
     *   6. SSE parse → extract response text
     *
     * @param {string} imageInput — Image data (base64, hex, data URI, or URL)
     * @param {string} [prompt='Describe this image in detail']
     * @returns {{ success: boolean, response?: string, description?: string, error?: string }}
     */
    static async analyzeImage(imageInput, prompt) {
        prompt = prompt || 'Describe this image in detail';

        return await Warp.withProxy(async function (proxyUrl, snapshot) {
            try {
                // ── Step 1: Authenticate via sentinel ──
                console.log('[Image] Starting image analysis flow...');
                var auth = await Sentinel.authenticate(proxyUrl, snapshot);

                // ── Step 2: Decode image input ──
                console.log('[Image] Decoding image input...');
                var decoded = await Helpers.decodeImageInput(imageInput, proxyUrl, auth.fp);
                console.log('[Image] Image decoded: ' + decoded.fileName + ' (' + decoded.data.length + ' bytes, ' + decoded.mimeType + ')');

                var baseHeaders = Headers.build(auth.config, auth.deviceId, auth.oaiBuildId);

                // ── Step 3: Initiate upload ──
                var uploadResult = await FileUpload.initiateUpload(
                    proxyUrl, auth.fp, baseHeaders,
                    decoded.fileName, decoded.data.length
                );

                // ── Step 4: Upload file to Azure Blob ──
                await FileUpload.uploadFile(
                    uploadResult.upload_url,
                    decoded.data,
                    decoded.mimeType
                );

                // ── Step 5: Process upload ──
                var processedFp = await FileUpload.processUpload(
                    proxyUrl, uploadResult.fp || auth.fp, baseHeaders,
                    uploadResult.file_id, decoded.fileName
                );

                // ── Step 6: Send multimodal message with image ──
                console.log('[Image] Sending multimodal conversation request...');
                var messageBody = ChatGPT.buildImageMessage(
                    uploadResult.file_id, decoded.fileName,
                    decoded.data.length, decoded.mimeType, prompt
                );

                var req = await fetch('https://chatgpt.com/backend-anon/conversation', {
                    method: 'POST',
                    fingerprint: processedFp || auth.fp,
                    agent: proxyUrl,
                    headers: Headers.build(auth.config, auth.deviceId, auth.oaiBuildId, {
                        'openai-sentinel-chat-requirements-token': auth.token,
                        'openai-sentinel-proof-token': auth.powAnswer || '',
                        'openai-sentinel-turnstile-token': auth.powAnswer || '',
                        'Accept': 'text/event-stream',
                        'X-Custom-Timeout': '120'
                    }),
                    body: messageBody
                });

                if (!req.ok) {
                    return { success: false, error: 'Image conversation failed: HTTP ' + req.status + ' — ' + (req.body || '').substring(0, 200) };
                }

                // ── Step 7: Parse SSE response ──
                var parsed = SSEParser.parse(req.body || '');

                if (!parsed.text && parsed.dataLineCount === 0) {
                    return { success: false, error: 'No data lines in image response: ' + parsed.raw };
                }
                if (!parsed.text) {
                    return { success: false, error: 'Could not extract text from ' + parsed.dataLineCount + ' SSE events. Raw: ' + parsed.raw };
                }

                console.log('[Image] ✅ Analysis received (' + parsed.text.length + ' chars)');
                return { success: true, response: parsed.text, description: parsed.text };

            } catch (err) {
                console.error('[Image] Error:', err);
                return { success: false, error: String(err) };
            }
        });
    }

    /**
     * Build the JSON body for a multimodal conversation with image attachment.
     *
     * @param {string} fileID    — Uploaded file ID
     * @param {string} fileName  — Original file name
     * @param {number} fileSize  — File size in bytes
     * @param {string} mimeType  — MIME type (e.g. 'image/png')
     * @param {string} prompt    — User prompt text
     * @returns {string} JSON string
     */
    static buildImageMessage(fileID, fileName, fileSize, mimeType, prompt) {
        var messageID = Helpers.generateUUID();

        var message = {
            id: messageID,
            author: { role: 'user' },
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
                    prompt
                ]
            },
            metadata: {
                attachments: [
                    {
                        id: fileID,
                        size: fileSize,
                        name: fileName,
                        mime_type: mimeType,
                        width: 1100,
                        height: 733,
                        source: 'local',
                        is_big_paste: false
                    }
                ],
                selected_github_repos: [],
                selected_all_github_repos: false,
                serialization_metadata: {
                    custom_symbol_offsets: []
                }
            }
        };

        return JSON.stringify({
            action: 'next',
            messages: [message],
            conversation_mode: { kind: 'primary_assistant' },
            history_and_training_disabled: true,
            is_visible: true,
            model: 'auto',
            supported_encodings: [],
            supports_buffering: false
        });
    }
}

module.exports = ChatGPT;

