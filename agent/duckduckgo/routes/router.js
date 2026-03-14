// agent/duckduckgo/routes/router.js
// Router layer — thin routing, delegates business logic to controllers

const ApiError = require('../errors/api-error.js');
const StatusController = require('../controllers/status.js');
const SearchController = require('../controllers/search.js');

class Router {
    constructor(stats) {
        this.stats = stats;
        this.statusCtrl = new StatusController(stats);
        this.searchCtrl = new SearchController(stats);
    }

    register(app) {
        var statusCtrl = this.statusCtrl;
        var searchCtrl = this.searchCtrl;
        var stats = this.stats;

        app.get('/', function (req, res) {
            statusCtrl.getStatus(req, res);
        });

        app.get('/v1/models', function (req, res) {
            statusCtrl.getModels(req, res);
        });

        app.post('/v1/chat/completions', ApiError.wrap(
            function (req, res) { return searchCtrl.chatCompletions(req, res); },
            stats,
            '[Search]'
        ));
    }

    static get ALLOWED_PATHS() {
        return ['/', '/v1/models', '/v1/chat/completions'];
    }

    static get MODELS() {
        return [
            { id: 'duckduckgo-search', object: 'model', owned_by: 'duckduckgo' },
            { id: 'web-search', object: 'model', owned_by: 'duckduckgo' }
        ];
    }
}

module.exports = Router;
