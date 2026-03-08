const core = require("./chatgpt_core.js");
const config = require("./config.js");

async function handleChat(req, res) {
    try {
        console.log("[CHAT] Processing free chat request");

        // Parse request body
        let bodyJson = req.bodyString;
        if (typeof bodyJson === 'string' && bodyJson.trim() !== "") {
            bodyJson = JSON.parse(bodyJson);
        }

        let prompt = "";
        if (bodyJson.messages && bodyJson.messages.length > 0) {
            prompt = bodyJson.messages[bodyJson.messages.length - 1].content;
        }

        if (!prompt) {
            throw new Error("No prompt found in request messages");
        }

        let cfg = config.get();

        let executeWithProxy = async (proxyUrl) => {
            // Initialize Core Client
            let client = new core.Client();
            client.proxyUrl = proxyUrl;
            await client.init();

            // Get Free Token via backend-anon
            let tokens = await client.generateToken();

            // Execute Completion
            let responseText = await client.executeConversation(prompt, tokens);

            // Format to OpenAI Standard Response
            let promptTokens = prompt.length / 4;
            let completionTokens = responseText.length / 4;

            return {
                id: "chatcmpl-" + Math.floor(Date.now() / 1000),
                object: "chat.completion",
                created: Math.floor(Date.now() / 1000),
                model: bodyJson.model || "gpt-4o",
                choices: [{
                    index: 0,
                    message: {
                        role: "assistant",
                        content: responseText
                    },
                    finish_reason: "stop"
                }],
                usage: {
                    prompt_tokens: promptTokens,
                    completion_tokens: completionTokens,
                    total_tokens: promptTokens + completionTokens
                }
            };
        };

        let runProxy = cfg.proxyUrl;
        if (runProxy && runProxy.includes("j2jsad9i9")) {
            let randomSession = Math.random().toString(36).substring(2, 11);
            runProxy = runProxy.replace("j2jsad9i9", randomSession);
            console.log("[CHAT] Using rotating proxy session ID: " + randomSession);
        }

        let stdResp = await executeWithProxy(runProxy);

        res.status(200).setHeader("Content-Type", "application/json").send(JSON.stringify(stdResp));

    } catch (err) {
        console.error("[CHAT] Error: " + err);
        res.status(500).json({ error: { message: "Internal server error: " + err.toString() } });
    }
}

module.exports = {
    handle: handleChat
};
