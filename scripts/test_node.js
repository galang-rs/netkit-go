// scripts/test_node.js
function init() {
    console.log("=== Testing Node.js Integration ===");
    try {
        const nodeApp = runNodeJS("scripts/node_test.js");

        console.log("Node Property (message):", nodeApp.message);

        const sum = nodeApp.add(10, 20);
        console.log("Node Function (add): 10 + 20 =", sum);

        const asyncRes = nodeApp.fetchTest();
        console.log("Node Async (fetchTest):", asyncRes);

        console.log("=== Test Complete ===");
    } catch (e) {
        console.error("Test Failed:", e);
    }
}

function onPacket(ctx) {
    // Not used for this test
}
