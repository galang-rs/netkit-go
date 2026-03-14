# Google AI Search Agent

Google Search with [AI mode](https://google.com/search?udm=50) as an OpenAI-compatible API — **no login, no API key required**.

Based on [google-ai-search-cli](https://github.com/KevCui/google-ai-search-cli) concept, adapted to the NetKit-Go agent architecture.

## How It Works

1. Receives OpenAI-format chat completion request
2. Extracts the last user message as a Google search query
3. Sends GET to `https://www.google.com/search?udm=50&q=<query>` via WARP proxy
4. Parses HTML response to extract AI Overview content
5. Returns clean markdown text in OpenAI-compatible format

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Service status |
| `GET`  | `/v1/models` | List available models |
| `POST` | `/v1/chat/completions` | Google AI Search (OpenAI-compatible) |

## Usage

### Start the agent

```bash
netkit-go --script agent/google/main.js
```

### Query examples

```bash
# Basic search
curl http://localhost:8081/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"google-ai-search","messages":[{"role":"user","content":"What is quantum computing?"}]}'

# Direct mode (no WARP proxy, uses server IP)
curl http://localhost:8081/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"google-ai-search","messages":[{"role":"user","content":"latest news today"}],"use_proxy":false}'

# Status check
curl http://localhost:8081/

# List models
curl http://localhost:8081/v1/models
```

## Architecture

```
agent/google/
├── main.js                  # Entry point
├── routes/router.js         # Route registration
├── controllers/
│   ├── search.js            # Chat completions handler
│   └── status.js            # Status & models handler
├── api/google-ai.js         # Public API (search orchestrator)
├── services/search.js       # Google HTTP service
├── core/
│   ├── helpers.js           # UUID, random utilities
│   └── html-parser.js       # HTML → markdown extractor
├── config/constants.js      # URLs, user agents
├── network/headers.js       # Browser headers builder
└── errors/api-error.js      # Centralized error handling
```

## Models

| Model ID | Description |
|----------|-------------|
| `google-ai-search` | Google AI Search mode (default) |
| `google-ai` | Alias for google-ai-search |

## Notes

- Uses WARP proxy by default for IP rotation (prevents rate limiting)
- Set `"use_proxy": false` in request body to use direct connection
- Google may occasionally return CAPTCHA challenges; WARP rotation helps mitigate this
- Port: **8081** (to avoid conflict with ChatGPT agent on 8080)
