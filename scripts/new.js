function init() {
    console.log("init() called");
    Proxy.Create({ addr: ":1080", type: "socks5" });
    Domain("*");
}

function onPacket(ctx) {
    if (!ctx.Flow.IsHTTP() && !ctx.Flow.IsWS()) return
    headers = ctx.Flow.Headers()?.Raw() || ""
    if (headers == 0 || headers == "" || headers.length == 0) return
    const url = ctx.Flow.FullURL;
    if (!url || url === "http://:0/") return;
    if (url.includes("cdn")) return;
    if (url.includes("ces")) return;
    if (url.includes("assets")) return;

    if ( //https://copilot.microsoft.com/
        url.includes("microsoft.com") ||
        url.includes("bing.com") ||
        url.includes("google.com")
    ) {
        const body = ctx.Flow.Body()
        const fullContent = body ? body.WaitFullContent() : null
        req = headers
        req += "\n\n"
        req += fullContent || ""

        // Only save if we have body content, or if this is a request (requests may not have body)
        const isResponse = FS.GetCache(ctx.Reference()) ? true : false
        const filename = "logs/" + ctx.Reference() + "/" + (isResponse ? "response" : "request") + ".txt"

        if (!isResponse || fullContent) {
            FS.SaveFile(filename, req)
            FS.SetCache(ctx.Reference(), true)
        }
    }
}

function onerror(ctx) {
    console.log(ctx.Error)
}
