// scripts/chatgpt/routes/router.js
// Router layer — thin routing, delegates business logic to controllers
// All handlers wrapped with ApiError.wrap() for centralized error handling

const ApiError = require('../errors/api-error.js');
const StatusController = require('../controllers/status.js');
const ChatController = require('../controllers/chat.js');
const ImageController = require('../controllers/image.js');

class Router {
    /**
     * @param {object} stats — shared mutable stats counters
     */
    constructor(stats) {
        this.stats = stats;
        this.statusCtrl = new StatusController(stats);
        this.chatCtrl = new ChatController(stats);
        this.imageCtrl = new ImageController(stats);
    }

    /**
     * Register all routes on the given HTTP server app.
     * Each async handler is wrapped with ApiError.wrap() for centralized error catching.
     * @param {object} app — http.createServer() instance
     */
    register(app) {
        var statusCtrl = this.statusCtrl;
        var chatCtrl = this.chatCtrl;
        var imageCtrl = this.imageCtrl;
        var stats = this.stats;

        // ── GET endpoints (sync, no error wrapping needed) ──
        app.get('/', function (req, res) {
            statusCtrl.getStatus(req, res);
        });

        app.get('/v1/models', function (req, res) {
            statusCtrl.getModels(req, res);
        });

        // ── POST endpoints (async, wrapped with error handler) ──
        app.post('/v1/chat/completions', ApiError.wrap(
            function (req, res) { return chatCtrl.chatCompletions(req, res); },
            stats,
            '[ChatGPT]'
        ));

        app.post('/v1/images/analyze', ApiError.wrap(
            function (req, res) { return imageCtrl.imageAnalyze(req, res); },
            stats,
            '[Image]'
        ));
    }

    /**
     * Allowed paths for onConnect firewall filter.
     */
    static get ALLOWED_PATHS() {
        return ['/', '/v1/models', '/v1/chat/completions', '/v1/images/analyze', '/ask'];
    }

    /**
     * Available model definitions.
     */
    static get MODELS() {
        return [
            { id: 'gpt-4o-mini', object: 'model', owned_by: 'openai' },
            { id: 'gpt-4o', object: 'model', owned_by: 'openai' },
            { id: 'gpt-4', object: 'model', owned_by: 'openai' },
            { id: 'gpt-3.5-turbo', object: 'model', owned_by: 'openai' },
            { id: 'gpt-5.2', object: 'model', owned_by: 'openai' }
        ];
    }
}

module.exports = Router;
