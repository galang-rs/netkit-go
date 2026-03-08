/**
 * security_audit.js
 * Demonstrates the new Firewall and Scope APIs.
 */

console.log("🛡️  Security Audit Script Loaded");

// 1. Initial State
console.log(`Current Role: ${Security.Scope.GetRole()}`);
console.log(`Initial Scope: ${Security.Scope.GetActiveScope()}`);

// 2. Add Firewall Rules
console.log("🛡️  Setting up Firewall rules...");
Security.Firewall.AddRule({
    name: "Block-Google-DNS",
    priority: 10,
    action: "DENY",
    direction: "OUT",
    dstIP: "8.8.8.8",
    protocol: "udp"
});

Security.Firewall.AddRule({
    name: "Log-Local-Traffic",
    priority: 100,
    action: "LOG",
    direction: "BOTH",
    dstIP: "192.168.0.0/16"
});

// 3. List Rules
const rules = Security.Firewall.ListRules();
console.log(`🛡️  Active Firewall Rules: ${rules.length}`);
rules.forEach(r => {
    console.log(`  - [${r.priority}] ${r.name}: ${r.action} ${r.dstIP || 'ANY'} (${r.protocol || 'ANY'})`);
});

// 4. Test Scope Change
// Set scope to PrivateOnly for 1 minute
console.log("⏱️  Restricting scope to PrivateOnly for 1 minute...");
Security.Scope.SetScope(0, 1, "Testing restriction"); // 0 = ScopePrivateOnly
console.log(`Active Scope: ${Security.Scope.GetActiveScope()} (Should be 0)`);

// 5. Integration Hooks
function onConnect(info) {
    console.log(`[Audit] Connection: ${info.Source} -> ${info.Dest} (${info.Type})`);

    // Check if banned
    const banned = Security.Bruteforce.GetBannedIPs();
    if (banned && banned.includes(info.Source)) {
        console.warn(`[Audit] 🚨 Connection from BANNED IP: ${info.Source}`);
    }
}

function onPacket(p) {
    // Audit log
}

console.log("✅ Security Audit configuration complete.");
