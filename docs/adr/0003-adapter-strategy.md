# ADR-0003: adapters use native callback APIs where they exist, minimal wrappers where they don't

Status: accepted · Date: 2026-07-11

## Context

Five stacks need scanning hooks. Existing OTel instrumentation packages (OpenLLMetry
etc.) produce spans but give no synchronous hook over content *before* span end, which
is where tracewarden's detectors run (events must be attached while the span is
recording).

## Decision

- **LangChain / LlamaIndex**: native extension points (callback handler, dispatcher
  event handler). No monkeypatching, version-stable.
- **OpenAI / Anthropic SDKs / MCP client / PydanticAI**: wrap the narrowest public
  method (`chat.completions.create`, `messages.create`, `ClientSession.call_tool` +
  `list_tools`, `Agent.run`) storing originals for clean uninstrument.
- All adapters funnel content through one seam (`tracewarden._hooks.scan`) with a
  `Surface` tag; detector failures are swallowed after a one-time warning — security
  telemetry must never take the host app down.
- Content is scanned, never copied onto spans. Cost/latency/content capture belongs
  to Langfuse/Phoenix; tracewarden only emits findings (with redacted evidence).

## Known limitations (documented in the adapter guide)

- Streaming responses: request side scanned, streamed output not reassembled (yet).
- PydanticAI in-graph tool calls: use `guarded_tool` or the MCP adapter.
- MCP tool descriptions are scanned on `list_tools` — the tool-poisoning surface.
