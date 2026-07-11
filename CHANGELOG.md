# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims
for [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-07-11

First public release.

### Added

- `security.event.*` OpenTelemetry attribute schema (span events + per-span
  summary attributes), proposed as a semantic-convention extension.
- `tracewarden.install()` — one-line wiring that augments an existing
  `TracerProvider` or creates an OTLP/HTTP one.
- Framework instrumentation adapters: LangChain, LlamaIndex, PydanticAI,
  OpenAI SDK, Anthropic SDK, MCP client. Explicit `llm_call` / `tool_call` /
  `memory_write` context managers and a `@guarded_tool` decorator.
- Pluggable, independently toggleable detector framework + span-enrichment
  pipeline.
- Detectors: secrets, PII, prompt-injection, tool-poisoning, scope-violation,
  memory-poisoning, anomalous-sequence, cost/loop, and an opt-in local-LLM
  classifier.
- Backend presentation glue for Langfuse and Phoenix; importable Grafana
  dashboard (Tempo/TraceQL).
- Fully local docker-compose demo stack (Collector + Tempo + Phoenix + Grafana)
  and a seeded example run.
- Alerting layer: rules + stdout / stream / file (JSONL) / webhook sinks.
- MkDocs Material documentation.

[0.1.0]: https://github.com/Lonkins/tracewarden/releases/tag/v0.1.0
