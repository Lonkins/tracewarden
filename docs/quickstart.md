---
title: Quickstart
---

# Quickstart

## Install

```bash
pip install tracewarden                 # core
pip install "tracewarden[openai,mcp]"   # + framework adapters you use
pip install "tracewarden[all]"          # every adapter
```

Adapter extras: `openai`, `anthropic`, `langchain`, `llamaindex`, `pydantic-ai`, `mcp`.

## One-line wiring

```python
import tracewarden

tracewarden.install(
    service_name="my-agent",
    instrument=["openai", "mcp"],   # activate the adapters you need
)
```

`install()` **augments** whatever OTel setup already exists:

1. If you pass `tracer_provider=`, it attaches to that.
2. Otherwise it attaches to the globally registered SDK `TracerProvider` (your
   Langfuse/Phoenix pipeline).
3. Otherwise it creates one with an OTLP/HTTP exporter
   (`OTEL_EXPORTER_OTLP_ENDPOINT`, default `http://localhost:4318`).

## Explicit instrumentation

When an adapter doesn't cover something, scan it yourself:

```python
from tracewarden import llm_call, tool_call, memory_write, guarded_tool
from tracewarden.schema import Surface

with llm_call(system="…", prompt=user_input) as scan:
    reply = call_model(...)
    scan.record(Surface.COMPLETION, reply)

@guarded_tool          # scans tool inputs and outputs
def lookup(city: str) -> str:
    ...
```

## Run the local demo stack

Fully local, zero spend: OTel Collector → Tempo + Phoenix, with Grafana
auto-provisioned.

```bash
git clone https://github.com/Lonkins/tracewarden && cd tracewarden
docker compose -f docker/docker-compose.yaml up -d
uv run python examples/seeded_run.py
```

The seeded run plants a secret, a prompt injection, a poisoned tool description,
and a memory-poisoning write. You'll see:

- **stderr alerts** for each high/critical finding, e.g.
  `[tracewarden] HIGH secret_leak detector=tracewarden.secrets …`
- findings in **Grafana** → *tracewarden — Security Events* (http://localhost:3000)
- the same spans in **Phoenix** (http://localhost:6006)

Tear down with `docker compose -f docker/docker-compose.yaml down -v`.

## Toggle detectors

Every detector is independently switchable, via config or env:

```python
from tracewarden import TracewardenConfig, DetectorToggles

cfg = TracewardenConfig(detectors=DetectorToggles(pii=False, llm=True))
tracewarden.install(config=cfg)
```

```bash
export TRACEWARDEN_DETECT_PII=false
export TRACEWARDEN_DETECT_LLM=true      # opt-in local classifier
```
