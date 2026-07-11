---
title: Wire into Langfuse / Phoenix
---

# Wire into your existing Langfuse / Phoenix

tracewarden emits standard OTel span events, so **any OTLP backend already
receives the findings**. The steps below are only about making them show up
nicely where you already look.

## The golden rule

Call `tracewarden.install()` **after** your backend SDK has set up its
`TracerProvider`. tracewarden detects the existing provider and attaches to it —
it does not create a second pipeline. See [ADR-0002](adr/index.md).

## Langfuse (self-hosted)

```python
from langfuse import Langfuse
import tracewarden

Langfuse()              # configures the OTel provider Langfuse reads
tracewarden.install(instrument=["openai"])   # attaches to it
```

Findings arrive as span events on the same traces Langfuse shows. The per-span
summary is mirrored to `langfuse.metadata.security.*`
(`event_count`, `max_severity`, `event_types`) so you can filter/group on
security in the Langfuse UI.

## Arize Phoenix (self-hosted)

```python
from phoenix.otel import register
import tracewarden

register()                                   # Phoenix's OTel provider
tracewarden.install(instrument=["openai"])   # attaches to it
```

The summary is also mirrored under `security.summary.*` (OpenInference-style),
so Phoenix surfaces it on the span.

## Plain OTLP (no backend SDK)

Point tracewarden at any collector:

```python
tracewarden.install(endpoint="http://localhost:4318")
```

or set `OTEL_EXPORTER_OTLP_ENDPOINT`. The bundled
[demo stack](grafana.md) is exactly this.

## Turning the mirrors off

They're additive and cheap, but if you don't want them:

```python
from tracewarden.pipeline import DetectionPipeline
# build the pipeline with annotate_backends=False and register it yourself,
# or leave install() defaults and ignore the extra attributes.
```
