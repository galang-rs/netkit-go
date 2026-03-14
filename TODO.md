tidak sesuai dengan harapan responsenya
```
{
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
  }

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