// agent/duckduckgo/controllers/status.js
// Controller for status & model listing endpoints

const Router = require('../routes/router.js');

class StatusController {
    constructor(stats) {
        this.stats = stats;
    }

    getStatus(req, res) {
        var s = this.stats;
        var uptimeSeconds = Math.floor((Date.now() - s.startTime) / 1000);
        res.json({
            status: 'running',
            service: 'web-search-api',
            description: 'DuckDuckGo search as OpenAI-compatible API — no login, no API key',
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
                'POST /v1/chat/completions    — Web Search (OpenAI-compatible)'
            ],
            example_curl: {
                simple: "curl http://localhost:8081/v1/chat/completions -H 'Content-Type: application/json' -d '{\"model\":\"web-search\",\"messages\":[{\"role\":\"user\",\"content\":\"What is quantum computing?\"}]}'",
                direct: "curl http://localhost:8081/v1/chat/completions -H 'Content-Type: application/json' -d '{\"model\":\"web-search\",\"messages\":[{\"role\":\"user\",\"content\":\"latest news today\"}],\"use_proxy\":false}'"
            }
        });
    }

    getModels(req, res) {
        res.json({
            object: 'list',
            data: Router.MODELS
        });
    }
}

module.exports = StatusController;
