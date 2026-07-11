---
title: Architecture decisions
---

# Architecture decision records

Design decisions are recorded as ADRs in the repo under `docs/adr/`.

- **[ADR-0001](https://github.com/Lonkins/tracewarden/blob/main/docs/adr/0001-security-event-schema.md)** — `security.event.*` schema: span events + span summary attributes.
- **[ADR-0002](https://github.com/Lonkins/tracewarden/blob/main/docs/adr/0002-augment-existing-tracer-provider.md)** — `install()` augments an existing `TracerProvider`, never replaces it.
- **[ADR-0003](https://github.com/Lonkins/tracewarden/blob/main/docs/adr/0003-adapter-strategy.md)** — adapters use native callback APIs where they exist, minimal wrappers where they don't.

Each ADR states context, decision, alternatives rejected, and consequences.
