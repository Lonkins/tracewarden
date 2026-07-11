---
title: tracewarden
---

# tracewarden

**Security-event trace layer for AI agents, built on OpenTelemetry.**

tracewarden *augments* your existing LLM observability (Langfuse, Arize Phoenix,
any OTLP backend). It auto-instruments agent frameworks and enriches the spans
you already emit with **security events** — prompt injection, secret/PII leakage,
tool poisoning, scope violations, memory poisoning, anomalous tool sequences, and
cost/loop anomalies — under a portable `security.event.*` attribute namespace.

Detectors run **locally and deterministically** by default. No hosted service,
no paid key, no replacement backend.

```python
import tracewarden

# Attach to your existing OTel/Langfuse/Phoenix setup and instrument your stack.
tracewarden.install(instrument=["openai", "mcp"])
```

That is enough for findings to start landing on your traces.

## What it is not

Not a general observability platform. Langfuse and Phoenix own cost/latency/quality
tracing; tracewarden extends them. The differentiator is **security-event detection
plus a portable schema** — so the same findings work across backends.

## Where to go next

- [Quickstart](quickstart.md) — install, instrument, run the local demo stack
- [Attribute schema](schema.md) — the `security.event.*` namespace
- [Detector catalog](detectors/catalog.md) — what fires, and why
- [Wire into Langfuse / Phoenix](backends.md)

## At a glance

| | |
|---|---|
| Frameworks | LangChain, LlamaIndex, PydanticAI, OpenAI SDK, Anthropic SDK, MCP client |
| Detectors | secrets, PII, prompt-injection, tool-poisoning, scope, memory-poisoning, anomalous-sequence, cost/loop, opt-in local-LLM |
| Export | OTLP/HTTP → any backend; Langfuse & Phoenix presentation glue; Grafana dashboard |
| Alerting | rules → stdout / file / webhook |
| Cost | zero — local detectors, free/OSS demo stack |
