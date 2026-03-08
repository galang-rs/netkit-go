async function init() {
    console.log("=== Complex Fingerprint Consistency Test ===");

    // Helper to get JA3/JA4
    async function getJA3(label, options = {}) {
        console.log(`[Test] ${label}...`);
        try {
            const resp = await fetch("https://tls.peet.ws/api/all", options);
            if (!resp.ok) {
                console.error(`[Test] ${label} failed with status:`, resp.status);
                return null;
            }
            const data = JSON.parse(resp.body);
            const ja3 = (data.tls && (data.tls.ja3 || data.tls.ja3_hash)) || "N/A";
            const ja4 = (data.tls && data.tls.ja4) || "N/A";
            console.log(`[Test] ${label} - JA3:`, ja3.substring(0, 50) + "...");
            console.log(`[Test] ${label} - JA4:`, ja4);

            return { ja3, ja4, fingerprint: resp.fingerprint };
        } catch (e) {
            console.error(`[Test] ${label} Error:`, e);
            return null;
        }
    }

    try {
        // 1. Initial request to capture fingerprint
        const res1 = await getJA3("Request 1 (Initial)");
        if (!res1) return;

        // Capture the fingerprint
        const fp = res1.fingerprint.snapshoot();
        console.log("[Test] Fingerprint captured.");

        // Wait a bit to avoid rate limits
        console.log("[Test] Waiting 2s...");
        for (let i = 0; i < 2000000; i++) { } // Primitive sleep

        // 2. Second request with captured fingerprint
        const res2 = await getJA3("Request 2 (Reused)", { fingerprint: fp });
        if (!res2) return;

        // 3. Third request WITHOUT profile/fingerprint
        console.log("[Test] Waiting 2s...");
        for (let i = 0; i < 2000000; i++) { } // Primitive sleep

        const res3 = await getJA3("Request 3 (Fresh)");
        if (!res3) return;

        // Comparison Result logic
        console.log("\n=== Consistency Results ===");
        const ja3Match = res1.ja3 === res2.ja3;
        const ja4Match = res1.ja4 === res2.ja4;

        if (!ja3Match) {
            console.log("❌ JA3 Mismatch!");
            console.log("Req 1:", res1.ja3);
            console.log("Req 2:", res2.ja3);
        } else {
            console.log("✅ JA3 Matches");
        }

        if (!ja4Match) {
            console.log("❌ JA4 Mismatch!");
            console.log("Req 1:", res1.ja4);
            console.log("Req 2:", res2.ja4);
        } else {
            console.log("✅ JA4 Matches");
        }

        const consistent = ja3Match && ja4Match;
        const different = res1.ja3 !== res3.ja3 || res1.ja4 !== res3.ja4;

        console.log(`- Summary R1 vs R2: ${consistent ? "✅ SAME (Consistent)" : "❌ DIFFERENT (Failure)"}`);
        console.log(`- Summary R1 vs R3: ${different ? "✅ DIFFERENT (Working)" : "⚠️ SAME (Randomness resulted in same profile)"}`);

        if (consistent && different) {
            console.log("\n✅ ALL TESTS PASSED: Snapshot reuse works and fresh requests generate new fingerprints.");
        } else if (consistent) {
            console.log("\n⚠️ Partially working: Snapshot reuse works, but fresh request used the same profile.");
        } else {
            console.log("\n❌ TEST FAILED: Snapshot reuse did not maintain consistency.");
        }

    } catch (e) {
        console.error("[Test] Unexpected error:", e);
    }
    Stop(null);
}
