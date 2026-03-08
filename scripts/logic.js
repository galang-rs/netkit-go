// scripts/logic.js
async function init() {
    console.log("=== Testing logic.js with Node.js bridge ===");
    try {
        const node = runNodeJS("scripts/node_test.js");

        console.log(node.greet("User"));
        console.log("Shuffled:", JSON.stringify(node.shuffle([1, 2, 3, 4, 5])));

        const data = node.getData();
        console.log("Async Data:", JSON.stringify(data));

        const fetchResult = await node.fetchTest();
        console.log("Fetch Result:", JSON.stringify(fetchResult));

        const token = node.generateToken();
        console.log("Generated Token:", token);

        const decoded = node.verifyToken(token);
        console.log("Decoded Token:", decoded);

        const rxResult = await node.rxTest();
        console.log("Rx Result:", rxResult);
    } catch (e) {
        console.error("Error in logic.js:", e);
    }
}

// Dummy handler to satisfy the engine (though no longer strictly required after my fix)
function onPacket(ctx) { }
