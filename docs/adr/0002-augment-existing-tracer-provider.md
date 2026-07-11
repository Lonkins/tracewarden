# ADR-0002: install() augments an existing TracerProvider, never replaces it

Status: accepted · Date: 2026-07-11

## Context

tracewarden's pitch is *augmenting* existing observability (Langfuse, Phoenix, plain
OTel). Users typically already have a TracerProvider configured when they call
`tracewarden.install()`.

## Decision

`install()` resolution order:

1. Explicit `tracer_provider=` argument (tests, multi-provider apps).
2. Globally registered SDK `TracerProvider` — attach only; no exporter added, the
   existing pipeline already ships spans.
3. None found — create a provider with an OTLP/HTTP `BatchSpanProcessor`
   (endpoint from arg → `OTEL_EXPORTER_OTLP_ENDPOINT` → SDK default
   `http://localhost:4318`) and register it globally.

`install()` is idempotent and returns a `TracewardenHandle`; `uninstall()` tears down
only what tracewarden created.

## Consequences

Zero config with the bundled compose stack; zero interference with an existing
Langfuse/Phoenix pipeline. The cost: when a provider exists, export failures are the
host app's concern — tracewarden never owns delivery in that mode.
