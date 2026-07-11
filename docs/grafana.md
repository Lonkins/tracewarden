---
title: Grafana dashboard
---

# Grafana dashboard

`dashboards/tracewarden-grafana.json` is an importable Grafana dashboard driven
by Tempo + TraceQL over the `security.event.*` schema.

## Panels

- **Overview stats** — spans with findings, secret leaks, prompt injections,
  critical findings
- **Recent spans by severity** — filtered by a `severity` template variable
- **Tool poisoning & scope violations** table

## In the demo stack

Grafana auto-provisions the datasource and this dashboard. Just:

```bash
docker compose -f docker/docker-compose.yaml up -d
uv run python examples/seeded_run.py
```

then open http://localhost:3000 → **tracewarden — Security Events**.

## In your own Grafana

1. Ensure a Tempo datasource exists.
2. **Dashboards → Import** → upload `dashboards/tracewarden-grafana.json`.
3. Pick your Tempo datasource when prompted.

The queries are plain TraceQL, e.g.

```
{ event.security.event.type = "secret_leak" } | count()
{ span.security.events.count > 0 }
```

so you can adapt them to any TraceQL-capable backend.
