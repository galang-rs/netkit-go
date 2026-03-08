const core = require("./chatgpt_core.js");

async function handleImages(req, res) {
    try {
        console.log("[IMAGES] Processing free images request");

        let bodyJson = req.bodyString;
        if (typeof bodyJson === 'string' && bodyJson.trim() !== "") {
            bodyJson = JSON.parse(bodyJson);
        }

        let prompt = bodyJson.prompt;
        if (!prompt) {
            throw new Error("No prompt provided for image generation");
        }

        // Initialize Core Client
        let client = new core.Client();
        await client.init();

        // Get Free Token via backend-anon
        let tokens = await client.generateToken();

        // Execute Completion for Images
        // Note: Free backend-anon usually doesn't support DALL-E directly via the conversation API. 
        // We will pass the image prompt to the text model as a fallback or if it has some image tool execution.
        let fullPrompt = "Generate an image for the following prompt: " + prompt;
        let responseText = await client.executeConversation(fullPrompt, tokens);

        let stdResp = {
            created: Math.floor(Date.now() / 1000),
            data: [{
                url: "N/A - Image Generation requires authenticated Plus account. Text response: " + responseText.substring(0, 100) + "..."
            }]
        };

        res.status(200).setHeader("Content-Type", "application/json").send(JSON.stringify(stdResp));

    } catch (err) {
        console.error("[IMAGES] Error: " + err);
        res.status(500).json({ error: { message: "Internal server error: " + err.toString() } });
    }
}

module.exports = {
    handle: handleImages
};
