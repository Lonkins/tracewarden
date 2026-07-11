# tracewarden

**Security-event trace layer for AI agents, built on OpenTelemetry.**

[![CI](https://github.com/Lonkins/tracewarden/actions/workflows/ci.yml/badge.svg)](https://github.com/Lonkins/tracewarden/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tracewarden.svg)](https://pypi.org/project/tracewarden/)
[![Python](https://img.shields.io/pypi/pyversions/tracewarden.svg)](https://pypi.org/project/tracewarden/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![mypy: strict](https://img.shields.io/badge/mypy-strict-blue.svg)](https://mypy.readthedocs.io/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

tracewarden *augments* your existing LLM observability (Langfuse, Arize Phoenix,
any OTLP backend). It auto-instruments agent frameworks and enriches the spans
you already emit with **security events** under a portable `security.event.*`
attribute namespace:

- 🪤 **prompt injection** (direct + indirect, via tool output / description / memory)
- 🔑 **secret & PII leakage** (regex + entropy, Luhn-gated cards)
- ☠️ **tool poisoning** (hidden instructions in MCP tool descriptions)
- 🚧 **scope / permission violations** (tool allowlist, sensitive-path access)
- 🧠 **memory-write poisoning** (Mem0 / vector-store persistence attacks)
- 🔁 **anomalous tool sequences** and **cost / loop anomalies**

Detectors run **locally and deterministically** by default. No hosted service,
no paid key, no replacement backend. tracewarden does not compete with Langfuse
or Phoenix — it **rides on top of them**.

---

## Install

```bash
pip install tracewarden                 # core
pip install "tracewarden[openai,mcp]"   # + the framework adapters you use
pip install "tracewarden[all]"          # every adapter
```

Adapters: `openai`, `anthropic`, `langchain`, `llamaindex`, `pydantic-ai`, `mcp`.

## Use

```python
import tracewarden

# Attaches to your existing OTel/Langfuse/Phoenix provider, or creates an
# OTLP/HTTP one; then instruments the frameworks you name.
tracewarden.install(instrument=["openai", "mcp"])
```

That's it — findings start landing on your traces. For code the adapters don't
cover, scan explicitly:

```python
from tracewarden import llm_call, guarded_tool
from tracewarden.schema import Surface

with llm_call(system="…", prompt=user_input) as scan:
    reply = call_model(...)
    scan.record(Surface.COMPLETION, reply)

@guarded_tool                    # scans tool inputs + outputs
def lookup(city: str) -> str: ...
```

## Alert on findings

```python
from tracewarden import AlertManager, AlertRule, stdout_sink, webhook_sink
from tracewarden.schema import Severity

tracewarden.install(on_events=AlertManager(
    rules=(AlertRule(min_severity=Severity.HIGH),),
    sinks=(stdout_sink, webhook_sink("https://hooks.example.com/tw")),
))
```

## See it end-to-end (zero spend, fully local)

```bash
git clone https://github.com/Lonkins/tracewarden && cd tracewarden
docker compose -f docker/docker-compose.yaml up -d      # Collector + Tempo + Phoenix + Grafana
uv run python examples/seeded_run.py                     # plants a secret + an injection
```

The seeded run trips the detectors and prints alerts:

```
[tracewarden] HIGH secret_leak detector=tracewarden.secrets rule=aws_access_key_id surface=tool_output …
[tracewarden] HIGH prompt_injection detector=tracewarden.prompt_injection surface=user_prompt …
[tracewarden] CRITICAL tool_poisoning detector=tracewarden.tool_poisoning rule=sensitive_file_read surface=tool_description …
```

The same findings appear in **Grafana** (http://localhost:3000 →
*tracewarden — Security Events*) and **Phoenix** (http://localhost:6006).

## How it fits

```
your agent (LangChain / LlamaIndex / PydanticAI / OpenAI / Anthropic / MCP)
        │  tracewarden auto-instruments
        ▼
   OTel spans ── security.event.* ──►  OTLP  ──►  Langfuse · Phoenix · Tempo/Grafana
        ▲                                                    (your existing backend)
        └── local detectors enrich spans in-process (regex, entropy, signatures,
            per-trace state; optional opt-in local LLM)
```

## The schema

Each finding is an OTel **span event** (`security.event`) with flat attributes
(`type`, `severity`, `confidence`, `detector`, `rule`, `surface`, `evidence`),
plus per-span summary attributes (`security.events.count|max_severity|types`).
Evidence is **always redacted** — raw matched content never leaves the process.
Full reference: [docs/schema.md](docs/schema.md).

## Documentation

Quickstart, detector catalog with tuning guidance, the attribute schema, and
"wire it into your existing Langfuse/Phoenix" live in [`docs/`](docs/) and build
with MkDocs Material (`uv run mkdocs serve`).

## Design

- Detectors are pluggable and independently toggleable; adding one is a class +
  a toggle + fixtures.
- `install()` **augments** an existing `TracerProvider`, never replaces it.
- Everything runs locally; the only network detector (LLM) is opt-in and defaults
  to a local model.

See the [ADRs](docs/adr/index.md).

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Detector fixtures
must be **synthetic**; never commit real secrets or PII. `mypy --strict`, `ruff`,
and the test suite gate every PR.

## License

[Apache-2.0](LICENSE)
