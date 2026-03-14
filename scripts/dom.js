// scripts/dom.js
// Demo: SauceDemo login flow — screenshot before & after login

async function init() {
    console.log("[DOM Demo] Starting SauceDemo login flow...");

    // 1. Fetch SauceDemo login page
    var resp = await fetch("https://www.saucedemo.com/");

    if (!resp || !resp.ok) {
        console.log("[DOM Demo] Fetch failed:", resp ? resp.error || resp.status : "no response");
        return;
    }

    console.log("[DOM Demo] Fetched, status:", resp.status);

    // 2. Parse HTML WITH executeScripts — React will render the login form!
    console.log("[DOM Demo] Parsing with executeScripts (React rendering)...");
    var doc = html(resp.body, {
        url: resp.url || "https://www.saucedemo.com/",
        executeScripts: true
    });

    console.log("[DOM Demo] Title:", doc.title());

    // 3. Check if React rendered the login form
    var usernameInput = doc.querySelector("#user-name");
    var passwordInput = doc.querySelector("#password");
    var loginBtn = doc.querySelector("#login-button");

    console.log("[DOM Demo] Username input:", usernameInput ? "FOUND ✓" : "NOT FOUND ✗");
    console.log("[DOM Demo] Password input:", passwordInput ? "FOUND ✓" : "NOT FOUND ✗");
    console.log("[DOM Demo] Login button:", loginBtn ? "FOUND ✓ (" + loginBtn.tag + ")" : "NOT FOUND ✗");

    // 4. Screenshot BEFORE login (initial page)
    doc.setViewport(1280, 900);
    doc.screenshot({ path: "logs/screenshot/saucedemo_01_before_login.png" });
    console.log("[DOM Demo] ✓ Screenshot saved: saucedemo_01_before_login.png");

    // 5. Type credentials
    if (usernameInput && passwordInput) {
        doc.type("#user-name", "standard_user");
        doc.type("#password", "secret_sauce");
        console.log("[DOM Demo] ✓ Typed credentials: standard_user / secret_sauce");

        // Screenshot after typing credentials
        doc.screenshot({ path: "logs/screenshot/saucedemo_02_credentials_typed.png" });
        console.log("[DOM Demo] ✓ Screenshot saved: saucedemo_02_credentials_typed.png");
    } else {
        console.log("[DOM Demo] ✗ Cannot type — form elements not found!");
        doc.close();
        return;
    }

    // 6. Click login button
    if (loginBtn) {
        console.log("[DOM Demo] Clicking login button...");
        var result = doc.click("#login-button");
        console.log("[DOM Demo] Click result:", result || "no navigation");

        // Screenshot AFTER login (final page)
        doc.screenshot({ path: "logs/screenshot/saucedemo_03_after_login.png" });
        console.log("[DOM Demo] ✓ Screenshot saved: saucedemo_03_after_login.png");

        // Full page screenshot
        doc.screenshot({ fullPage: true, path: "logs/screenshot/saucedemo_04_after_login_full.png" });
        console.log("[DOM Demo] ✓ Full page screenshot saved: saucedemo_04_after_login_full.png");

        // Show new page info
        console.log("[DOM Demo] New page title:", doc.title());
        var allLinks = doc.links();
        console.log("[DOM Demo] Links on new page:", allLinks ? allLinks.length : 0);
    } else {
        console.log("[DOM Demo] ✗ Cannot click — login button not found!");
    }

    // 7. Save final HTML
    FS.SaveFile("logs/screenshot/saucedemo_final.html", doc.serialize());
    console.log("[DOM Demo] ✓ HTML saved: saucedemo_final.html");

    doc.close();
    console.log("[DOM Demo] Done!");
}
