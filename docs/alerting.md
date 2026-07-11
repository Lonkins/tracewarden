---
title: Alerting
---

# Alerting

A small rule layer fires on security-event classes and dispatches to sinks.
Wire it in through `install(on_events=...)`.

```python
import tracewarden
from tracewarden import AlertManager, AlertRule, stdout_sink, file_sink, webhook_sink
from tracewarden.schema import Severity, EventType

alerts = AlertManager(
    rules=(
        AlertRule(min_severity=Severity.HIGH),                                   # any high+
        AlertRule(min_severity=Severity.LOW, types=frozenset({EventType.SECRET_LEAK})),  # all secrets
    ),
    sinks=(
        stdout_sink,                       # -> stderr
        file_sink("alerts.jsonl"),         # -> JSONL
        webhook_sink("https://hooks.example.com/tracewarden"),  # -> JSON POST
    ),
)

tracewarden.install(on_events=alerts)
```

## Rules

`AlertRule(min_severity=, types=, name=)`:

- `min_severity` — fire only at/above this severity (`low`…`critical`).
- `types` — optional set of `EventType`; omit to match any type.

Each finding is dispatched **once** even if several rules match it.

## Sinks

| Sink | Destination | Notes |
|---|---|---|
| `stdout_sink` | stderr | human-readable line |
| `stream_sink(stream)` | any `TextIO` | your own stream |
| `file_sink(path)` | JSONL file | one JSON object per line |
| `webhook_sink(url)` | HTTP POST | stdlib JSON POST; failures logged, never raised |

A failing sink never blocks the others, and a webhook error never propagates
into your agent. Alerting, like detection, must not take the app down.

## Custom sinks

A sink is any `Callable[[Alert], None]`:

```python
def to_slack(alert):
    post_to_slack(alert.format_line())     # or alert.to_dict()

AlertManager(sinks=(to_slack,))
```
