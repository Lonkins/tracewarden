---
title: Tuning & false positives
---

# Tuning and false positives

A detector nobody trusts is worse than no detector — teams learn to ignore a
noisy panel. tracewarden ships conservative defaults; tune from there.

## Turn detectors off you don't need

```python
from tracewarden import TracewardenConfig, DetectorToggles
cfg = TracewardenConfig(detectors=DetectorToggles(pii=False, cost_loop=False))
```

or per-env: `TRACEWARDEN_DETECT_PII=false`.

## Config knobs

| Setting | Env | Default | Effect |
|---|---|---|---|
| `scope_allowed_tools` | `TRACEWARDEN_SCOPE_ALLOWED_TOOLS` (csv) | none | allowlisted tools; others flagged |
| `repeat_threshold` | `TRACEWARDEN_REPEAT_THRESHOLD` | 3 | identical repeats before flagging |
| `llm_call_budget` | `TRACEWARDEN_LLM_CALL_BUDGET` | 25 | model calls per trace before cost anomaly |
| `tool_fanout_threshold` | `TRACEWARDEN_TOOL_FANOUT_THRESHOLD` | 15 | distinct tools per trace before fan-out |

## Common false positives and what to do

- **Secrets on placeholders** (`YOUR_API_KEY_HERE`): already entropy-gated. If a
  low-entropy internal format still fires, it will be a specific rule — open an
  issue with a synthetic example so the gate can be tuned.
- **PII phone numbers**: lowest confidence (0.5). Filter alerts on
  `confidence >= 0.8` if phone noise bothers you.
- **Prompt injection in legitimate content**: summarizers quoting "ignore the
  previous section" score below the flag threshold on a single weak signal —
  flagging needs a strong signature or two combined. If your domain text trips
  it, disable the detector for that surface or lower its weight via a fork.
- **Cost/loop on legitimately long agents**: raise `llm_call_budget`.

## Filtering at the alert layer

You don't have to change detectors to cut noise — filter where you alert:

```python
from tracewarden import AlertManager, AlertRule, EventType
from tracewarden.schema import Severity

alerts = AlertManager(rules=(
    AlertRule(min_severity=Severity.HIGH),
    AlertRule(min_severity=Severity.MEDIUM, types=frozenset({EventType.SECRET_LEAK})),
))
```

## Writing your own detector

Implement the `Detector` interface, register it against a toggle, ship fixtures
with positive **and** negative cases. See `CONTRIBUTING.md` and
[ADR-0003](../adr/index.md).
