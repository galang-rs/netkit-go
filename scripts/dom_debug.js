// scripts/dom_debug.js - Debug version to check navigation type
async function init() {
    console.log("[Debug] Starting...");

    var resp = await fetch("https://www.google.com/search?q=&sca_esv=5a6a5bfff728b5c5&sxsrf=ANbL-n5pBqjh5u1Aa8qZm57-tfgtEWx2Hg%3A1773548266217&source=hp&ei=6jK2aam9CqGq4-EP07S2kA4&iflsig=AFdpzrgAAAAAabZA-tVJSKcIpHSC6kqDCKebuyigHasS&aep=22&udm=50&ved=0ahUKEwip2paThqGTAxUh1TgGHVOaDeIQteYPCBc&oq=&gs_lp=Egdnd3Mtd2l6IgBIAFAAWABwAHgAkAEAmAEAoAEAqgEAuAEByAEAmAIAoAIAmAMAkgcAoAcAsgcAuAcAwgcAyAcAgAgA&sclient=gws-wiz");
    if (!resp || !resp.ok) {
        console.log("[Debug] Fetch failed");
        return;
    }

    var doc = html(resp.body, {
        url: resp.url || "https://www.google.com/search?q=&sca_esv=5a6a5bfff728b5c5&sxsrf=ANbL-n5pBqjh5u1Aa8qZm57-tfgtEWx2Hg%3A1773548266217&source=hp&ei=6jK2aam9CqGq4-EP07S2kA4&iflsig=AFdpzrgAAAAAabZA-tVJSKcIpHSC6kqDCKebuyigHasS&aep=22&udm=50&ved=0ahUKEwip2paThqGTAxUh1TgGHVOaDeIQteYPCBc&oq=&gs_lp=Egdnd3Mtd2l6IgBIAFAAWABwAHgAkAEAmAEAoAEAqgEAuAEByAEAmAIAoAIAmAMAkgcAoAcAsgcAuAcAwgcAyAcAgAgA&sclient=gws-wiz",
        executeScripts: true
    });

    console.log("[Debug] Title:", doc.title());

    // Save final HTML
    FS.SaveFile("logs/screenshot/debug_final.html", doc.serialize());
    console.log("[Debug] Saved debug_final.html");

    doc.close();
    console.log("[Debug] Done");
}
