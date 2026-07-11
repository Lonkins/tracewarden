---
title: Attribute schema
---

# The `security.event.*` schema

tracewarden records each finding as an OTel **span event** named `security.event`,
plus **span summary attributes** so backends that index span attributes (but not
event attributes) can still filter. This is proposed as a semantic-convention
extension so findings are portable across backends. See
[ADR-0001](adr/index.md).

## Span event: `security.event`

One event per finding, with a flat attribute set:

| Attribute | Type | Example | Notes |
|---|---|---|---|
| `security.event.type` | string | `secret_leak` | closed set (below) |
| `security.event.severity` | string | `high` | `low` \| `medium` \| `high` \| `critical` |
| `security.event.confidence` | double | `0.9` | `0.0`–`1.0` |
| `security.event.detector` | string | `tracewarden.secrets` | detector id |
| `security.event.rule` | string | `aws_access_key_id` | which rule matched |
| `security.event.surface` | string | `tool_output` | where the content was seen |
| `security.event.evidence` | string | `AK…LE (len=20)` | **always redacted** |

## Span summary attributes

Set on any span that carries ≥1 finding, aggregated across all of them:

| Attribute | Type | Example |
|---|---|---|
| `security.events.count` | int | `2` |
| `security.events.max_severity` | string | `critical` |
| `security.events.types` | string[] | `["prompt_injection","secret_leak"]` |

Backend presentation mirrors (Langfuse / Phoenix) duplicate the summary under
`langfuse.metadata.security.*` and `security.summary.*` — see
[Backends](backends.md).

## Event types

`prompt_injection`, `secret_leak`, `pii_leak`, `tool_poisoning`,
`scope_violation`, `memory_poisoning`, `anomalous_sequence`, `cost_anomaly`,
`loop_anomaly`.

## Surfaces

`system_prompt`, `user_prompt`, `completion`, `tool_input`, `tool_output`,
`tool_description`, `memory_write`.

## Evidence is always redacted

Raw matched content never leaves the process. Evidence is masked to
first/last characters plus length (`redact()`), so the trace backend never
becomes a second copy of a leaked secret.
