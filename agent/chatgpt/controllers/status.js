// scripts/chatgpt/controllers/status.js
// Controller for status & model listing endpoints

const Router = require('../routes/router.js');

class StatusController {
    /**
     * @param {object} stats — shared stats counters reference
     */
    constructor(stats) {
        this.stats = stats;
    }

    /**
     * GET / — Service status & info
     */
    getStatus(req, res) {
        var s = this.stats;
        var uptimeSeconds = Math.floor((Date.now() - s.startTime) / 1000);
        res.json({
            status: 'running',
            service: 'chatgpt-free-api',
            uptime: uptimeSeconds,
            total_requests: s.requestCount,
            success_count: s.successCount,
            failure_count: s.failureCount,
            total_tokens: {
                input: s.totalInputTokens,
                output: s.totalOutputTokens,
                total: s.totalInputTokens + s.totalOutputTokens
            },
            available_models: Router.MODELS.map(function (m) { return m.id; }),
            endpoints: [
                'GET  /                       — Status',
                'GET  /v1/models              — List models',
                'POST /v1/chat/completions    — OpenAI-compatible chat',
                'POST /v1/images/analyze      — Image analysis (URL/base64/hex)'
            ],
            example_curl: {
                simple: "curl http://43.129.58.116:8080/v1/chat/completions -H 'Content-Type: application/json' -d '{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'",
                nested: "curl http://43.129.58.116:8080/v1/chat/completions -H 'Content-Type: application/json' -d '{\"model\":\"gpt-5.2\",\"messages\":[{\"role\":\"system\",\"content\":\"You are a helpful assistant\"},{\"role\":\"user\",\"content\":\"plan apa yang aku pakai sekarang\"},{\"role\":\"assistant\",\"content\":\"Kamu sedang memakai Free Tier.\"},{\"role\":\"user\",\"content\":\"boleh jelaskan\"}]}'"
            }
        });
    }

    /**
     * GET /v1/models — List available models
     */
    getModels(req, res) {
        res.json({
            object: 'list',
            data: Router.MODELS
        });
    }
}

module.exports = StatusController;
