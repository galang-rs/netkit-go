const chat = require("./chat.js");
const images = require("./images.js");

function start(port) {
    const app = http.createServer();

    // Global middleware for logging and CORS
    app.use((req, res, next) => {
        console.log(`[HTTP] ${req.method} ${req.path}`);

        // CORS Setup
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

        if (req.method === "OPTIONS") {
            return res.status(200).send("");
        }

        next();
    });

    // API Routes
    app.post("/v1/chat/completions", chat.handle);
    app.post("/v1/images/generations", images.handle);

    // Start App
    app.listen(port);
    console.log(`🚀 NetKit JS Proxy API listening on port ${port} (Pure JS Mode)`);
}

module.exports = {
    start: start
};
