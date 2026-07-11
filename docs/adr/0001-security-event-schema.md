# ADR-0001: security.event.* schema — span events + span summary attributes

Status: accepted · Date: 2026-07-11

## Context

Findings must be portable across OTLP backends (Langfuse, Phoenix, Tempo/Grafana,
vendor APMs) without a custom exporter per backend. A span can carry multiple findings.

## Decision

- Each finding is an OTel **span event** named `security.event` with flat attributes:
  `security.event.type|severity|confidence|detector|rule|surface|evidence`.
- Each enriched span also gets **summary attributes** (`security.events.count`,
  `security.events.max_severity`, `security.events.types`) because several backends and
  query layers (TraceQL, Langfuse UI filters) index span attributes but not event
  attributes.
- Enums are lowercase snake strings, closed sets (`EventType`, `Severity`, `Surface`).
- `evidence` is always redacted (`redact()` — first/last chars + length). Raw matched
  content never leaves the process; the trace store must not become a copy of the leak.
- Namespace is written as a proposed OTel semantic-convention extension
  (docs/schema page) rather than a private format.

## Alternatives rejected

- **One span attribute blob (JSON string)** — opaque to every query layer.
- **Separate log records** — breaks the "events live on the trace you already have"
  goal; correlation becomes the user's problem.
- **Child spans per finding** — pollutes latency views and span counts in
  cost/latency-oriented tools.

## Consequences

Backends that only show span attributes still get count/max-severity/types filters;
event-level detail is there for backends that surface span events. Schema changes are
additive-only until 1.0.
