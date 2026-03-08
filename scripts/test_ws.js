// scripts/test_ws.js
// NetKit WebSocket Echo Server Test

function init() {
    console.log("[JS] WebSocket Test Script Started");

    if (typeof ws === 'undefined') {
        console.error("❌ WebSocket module not found!");
        return;
    }

    const server = ws.createServer();

    server.on('connection', (socket) => {
        console.log(`[WS] 🤝 New connection from ${socket.remoteAddr}`);

        socket.on('message', (msg) => {
            console.log(`[WS] 📩 Received: ${msg}`);
            socket.send(`Echo from NetKit: ${msg}`);
        });

        socket.on('close', () => {
            console.log(`[WS] 🛑 Connection closed for ${socket.remoteAddr}`);
        });

        socket.send("Welcome to NetKit-Go WebSocket Server!");
    });

    const port = 8081;
    server.listen(port);
    console.log(`[JS] WS Server listening on port ${port}`);
}

// NetKit expects global hooks
function onConnect(info) {
    // onConnect still works for WS!
    if (info.Type === "js_ws_server") {
        console.log(`[Security] WS Connection Attempt: ${info.Source}`);
    }
}
