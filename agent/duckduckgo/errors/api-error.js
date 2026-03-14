// agent/duckduckgo/errors/api-error.js
// Centralized API error class with OpenAI-compatible error response format

class ApiError {
    /**
     * @param {number} status   — HTTP status code
     * @param {string} message  — Human-readable error message
     * @param {string} type     — Error type (OpenAI-compatible)
     */
    constructor(status, message, type) {
        this.status = status;
        this.message = message;
        this.type = type || 'server_error';
    }

    toJSON() {
        return {
            error: {
                message: this.message,
                type: this.type
            }
        };
    }

    send(res) {
        res.status(this.status).json(this.toJSON());
    }

    // ── Factory methods ─────────────────────────────────────────────────

    static badRequest(message) {
        return new ApiError(400, message, 'invalid_request_error');
    }

    static invalidJSON() {
        return new ApiError(400, 'Invalid JSON body', 'invalid_request_error');
    }

    static missingField(field) {
        return new ApiError(400, field + ' is required', 'invalid_request_error');
    }

    static upstream(message) {
        return new ApiError(502, message || 'Upstream request failed', 'upstream_error');
    }

    static internal(err) {
        return new ApiError(500, 'Internal server error: ' + String(err), 'server_error');
    }

    // ── Error handler wrapper ───────────────────────────────────────────

    /**
     * Wrap an async handler with centralized error catching.
     * @param {function} handler — async (req, res) => void
     * @param {object}   [stats] — optional stats to increment failureCount
     * @param {string}   [tag]   — log tag e.g. '[Google]'
     * @returns {function} wrapped handler
     */
    static wrap(handler, stats, tag) {
        tag = tag || '[Server]';
        return async function (req, res) {
            try {
                await handler(req, res);
            } catch (err) {
                if (stats) stats.failureCount++;

                if (err instanceof ApiError) {
                    console.error(tag + ' Error:', err.message);
                    err.send(res);
                } else {
                    console.error(tag + ' ❌ Unexpected error:', err);
                    ApiError.internal(err).send(res);
                }
            }
        };
    }
}

module.exports = ApiError;
