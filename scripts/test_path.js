// test_path.js
function onConnect(info) {
    console.log(`[JS OnConnect] Type: ${info.Type}, Dest: ${info.Dest}, Path: ${info.Path}`);
    return null;
}

function onPacket(ctx) {
    return null;
}
