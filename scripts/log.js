function init() {
    console.log("init() called");
    Proxy.Create({ addr: ":1080", type: "socks5" });
    Domain("*");
    
    // Explicitly enable hooks
    setFunc({
        onRequest: "onRequest",
        onResponse: "onResponse",
        onError: "onError"
    });
}

const seenLogs = new Set(); 

function onError(err) {
    console.error(`[JS Error] ${err}`);
}

function onRequest(ctx) {
    try {
        const url = ctx.FullURL;
        if (!url || url === "http://:0/") return;

        const flow = ctx.Flow;
        const flowID = flow.ID();
        const ref = ctx.Reference();
        const metadata = ctx.Packet.Metadata;
        const isDecrypted = metadata.Decrypted || false;
        
        const body = flow.Body();
        const fullBody = body.WaitFullContent() || "";
        const rawBody = body.Raw() || "";
        const rawHeaders = flow.Headers()?.Raw() || "";
        
        // Extract Content-Type from raw headers manually since ContentType() is missing
        let contentType = "N/A";
        const ctMatch = rawHeaders.match(/Content-Type:\s*(.*)/i);
        if (ctMatch) contentType = ctMatch[1].trim();
        
        const snapshot = flow.Snapshot();
        const method = snapshot.method || "UNKNOWN";

        const logPrefix = `[REQ][${ref}][Decrypted: ${isDecrypted}][Session: ${flowID}]\n` +
                          `URL: ${method} ${url}\n` +
                          `Content-Type: ${contentType}\n\n`;

        FS.SaveFile(`logs/${ref}_req_headers.txt`, logPrefix + rawHeaders);
        if (fullBody) FS.SaveFile(`logs/${ref}_req_body_decoded.txt`, fullBody);
        if (rawBody) FS.SaveFile(`logs/${ref}_req_body_raw.txt`, rawBody);
        
    } catch (e) {
        console.error(`[onRequest Error] ${e}`);
    }
}

function onResponse(ctx) {
    try {
        const url = ctx.FullURL;
        const flow = ctx.Flow;
        const flowID = flow.ID();
        const ref = ctx.Reference();
        const metadata = ctx.Packet.Metadata;
        const isDecrypted = metadata.Decrypted || false;

        const body = flow.Body();
        const fullBody = body.WaitFullContent() || "";
        const rawBody = body.Raw() || "";
        const rawHeaders = flow.Headers()?.Raw() || "";
        
        let contentType = "N/A";
        const ctMatch = rawHeaders.match(/Content-Type:\s*(.*)/i);
        if (ctMatch) contentType = ctMatch[1].trim();

        let encoding = "identity";
        const encMatch = rawHeaders.match(/Content-Encoding:\s*(.*)/i);
        if (encMatch) encoding = encMatch[1].trim();
        
        const snapshot = flow.Snapshot();
        const status = snapshot.statusCode || snapshot.status || "UNKNOWN";

        const logPrefix = `[RES][${ref}][Decrypted: ${isDecrypted}][Session: ${flowID}]\n` +
                          `Status: ${status} for ${url}\n` +
                          `Content-Type: ${contentType}\n` +
                          `Content-Encoding: ${encoding}\n\n`;

        FS.SaveFile(`logs/${ref}_res_headers.txt`, logPrefix + rawHeaders);
        if (fullBody) FS.SaveFile(`logs/${ref}_res_body_decoded.txt`, fullBody);
        if (rawBody) FS.SaveFile(`logs/${ref}_res_body_raw.txt`, rawBody);
        
    } catch (e) {
        console.error(`[onResponse Error] ${e}`);
    }
}

function onAds(ctx) { }

function closing() {
    console.log("Saving metrics before exit...");
}
