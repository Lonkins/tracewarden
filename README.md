# tracewarden

Security-event trace layer for AI agents, built on OpenTelemetry.

tracewarden augments existing LLM observability (Langfuse, Arize Phoenix, any OTLP backend)
with **security events**: prompt injection, secret/PII leakage, tool poisoning, scope
violations, memory poisoning, anomalous tool sequences, and cost/loop anomalies — detected
locally and deterministically, attached to your existing traces under a portable
`security.event.*` attribute namespace.

Full README lands with the first feature release. Repo bootstrap in progress.

## License

Apache-2.0
