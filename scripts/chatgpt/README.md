# ChatGPT Free API

This script exposes an OpenAI-compatible HTTP API using the free ChatGPT interface.

## Service URL
- **Base URL:** `http://43.129.58.116:8080/`

## API Endpoints

| Endpoint | Method | Description |
| --- | --- | --- |
| `/` | `GET` | Service status and usage examples |
| `/v1/models` | `GET` | List available AI models |
| `/v1/chat/completions` | `POST` | Chat completions (text + image + function calling) |
| `/v1/images/analyze` | `POST` | Image analysis (standalone) |

## Example Usage

### Simple Chat Completion
```bash
curl http://43.129.58.116:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```

### Multi-turn (Nested) Chat
```bash
curl http://43.129.58.116:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-5.2",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant"},
      {"role": "user", "content": "plan apa yang aku pakai sekarang"},
      {"role": "assistant", "content": "Kamu sedang memakai Free Tier."},
      {"role": "user", "content": "boleh jelaskan"}
    ]
  }'
```

### Function Calling (Tool Calling)

#### Step 1: Send request with tools
```bash
curl http://43.129.58.116:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "What is the weather in Jakarta?"}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "get_weather",
          "description": "Get current weather for a location",
          "parameters": {
            "type": "object",
            "properties": {
              "location": {"type": "string", "description": "City name"}
            },
            "required": ["location"]
          }
        }
      }
    ]
  }'
```

**Response** (model decides to call a function):
```json
{
  "id": "chatcmpl-abc123...",
  "object": "chat.completion",
  "model": "gpt-4o-mini",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": null,
      "tool_calls": [{
        "id": "call_abc123...",
        "type": "function",
        "function": {
          "name": "get_weather",
          "arguments": "{\"location\":\"Jakarta\"}"
        }
      }]
    },
    "finish_reason": "tool_calls"
  }]
}
```

#### Step 2: Send tool results back
```bash
curl http://43.129.58.116:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "What is the weather in Jakarta?"},
      {"role": "assistant", "content": null, "tool_calls": [{"id": "call_abc123", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"Jakarta\"}"}}]},
      {"role": "tool", "tool_call_id": "call_abc123", "content": "{\"temperature\": 32, \"unit\": \"C\", \"condition\": \"Sunny\"}"}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "get_weather",
          "description": "Get current weather for a location",
          "parameters": {
            "type": "object",
            "properties": {
              "location": {"type": "string", "description": "City name"}
            },
            "required": ["location"]
          }
        }
      }
    ]
  }'
```

**Response** (model uses the tool result to answer):
```json
{
  "choices": [{
    "message": {
      "role": "assistant",
      "content": "The weather in Jakarta is currently 32°C and sunny."
    },
    "finish_reason": "stop"
  }]
}
```

### Chat + Image Analysis (Unified)
Add `image_url` to any user message to attach an image:
```bash
curl http://43.129.58.116:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [
      {"role": "user", "content": "What is in this image?", "image_url": "https://example.com/photo.jpg"}
    ]
  }'
```

### Multi-turn with Image (Mixed Text + Image)
Previous conversation context is preserved alongside the image:
```bash
curl http://43.129.58.116:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [
      {"role": "user", "content": "Describe this image", "image_url": "data:image/png;base64,iVBOR..."},
      {"role": "assistant", "content": "The image shows a landscape with mountains."},
      {"role": "user", "content": "What colors are dominant?"}
    ]
  }'
```

### Image Analysis (Standalone Endpoint)
```bash
curl http://43.129.58.116:8080/v1/images/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "image_url": "https://example.com/photo.jpg",
    "prompt": "Describe this image"
  }'
```

### Check Available Models
```bash
curl http://43.129.58.116:8080/v1/models
```

## Message Format

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `role` | `string` | Yes | `user`, `assistant`, `system`, or `tool` |
| `content` | `string` | Yes | Text content of the message |
| `image_url` | `string` | No | Image source: URL, base64, hex, or data URI |
| `tool_calls` | `array` | No | Tool calls (in assistant messages) |
| `tool_call_id` | `string` | No | Tool call ID (in tool result messages) |

Alternative image fields: `image`, `image_data` (all map to the same input).

## Tools Format

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `type` | `string` | Yes | Must be `"function"` |
| `function.name` | `string` | Yes | Function name |
| `function.description` | `string` | No | Function description |
| `function.parameters` | `object` | No | JSON Schema for parameters |

## Response Format

All endpoints return OpenAI-compatible chat completion format:

```json
{
  "id": "chatcmpl-abc123...",
  "object": "chat.completion",
  "created": 1710000000,
  "model": "gpt-4o-mini",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "The image shows..."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 50,
    "completion_tokens": 100,
    "total_tokens": 150
  }
}
```

When the model calls tools, `finish_reason` is `"tool_calls"` and the message includes a `tool_calls` array instead of `content`.

