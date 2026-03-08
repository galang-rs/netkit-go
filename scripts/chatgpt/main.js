const netkit = require("./netkit.js");

function init() {
    console.log("========================================");
    console.log("   Initializing Modular NetKit REST API ");
    console.log("========================================");

    // Start proxy for backend connections
    const proxyUrl = "socks5://samdues_N0XCSmx2JdeQvrE:uoJel32HCIkQ5rm_country-id_session-gdbywudsa_lifetime-1h_streaming-1@sg.geo.proxyaz.net:51200";
    console.log(`[Proxy] Configuring HTTP fetch to route via: ${proxyUrl}`);

    // Set configuration
    const config = require("./config.js");
    config.set({ proxyUrl: proxyUrl });

    // Start the REST API on port 8080
    netkit.start(8080);
}

function closing() {
    console.log("🛑 API stopped.");
}
