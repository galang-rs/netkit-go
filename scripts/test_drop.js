// test_drop.js
function onConnect(info) {
    if (info.Dest.includes("drop.me")) {
        console.log(`[JS OnConnect] DROPPING connection to: ${info.Dest}`);
        info.Drop();
    }
    return null;
}

function onPacket(ctx) {
    return null;
}
