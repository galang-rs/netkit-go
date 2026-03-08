// test_race.js
// This script stresses the VM with concurrent HTTP requests and timers
// to verify that the synchronization fix prevents panics.

function onConnect(info) {
    return null;
}

function onRequest(ctx) {
    // Perform some VM operations
    const ip = ctx.Conn.ip || "unknown";
    const path = ctx.FullURL;

    // Random timer to increase concurrency overlap
    setTimeout(() => {
        console.log(`[Race Test] Timer for ${ip} on path ${path}`);
    }, Math.random() * 100);
}

// Start a local HTTP server to trigger onRequest concurrently
const server = http.Create({ addr: "127.0.0.1:9091" });
server.get("/test", (req, res) => {
    res.send("OK");
});

console.log("[Race Test] Started stress server on 127.0.0.1:9091");

// Self-stress loop
setInterval(() => {
    fetch("http://127.0.0.1:9091/test").then(r => {
        // console.log("Fetch OK");
    });
}, 10);
