# Contributing to tracewarden

Thanks for your interest. Contributions of all kinds are welcome: detectors, framework
adapters, docs, and bug reports.

## Development setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Lonkins/tracewarden
cd tracewarden
uv sync --all-extras --dev
uv run pre-commit install
```

## Workflow

1. Branch from `main`.
2. Make your change with tests and docs.
3. `uv run pre-commit run --all-files` and `uv run pytest` must pass locally.
4. Open a PR. CI (lint, types, tests, secret scan, build) must be green.
5. PRs are squash-merged.

## Standards

- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, ...).
- `mypy --strict` clean; full type annotations.
- New detectors need synthetic fixtures only — never commit real secrets or PII,
  even expired ones.
- Detectors must run locally and deterministically by default. Anything that calls
  a model must be opt-in and default to a local backend.

## Adding a detector

See `docs/` for the detector catalog and the `Detector` interface. A new detector needs:
a class implementing the interface, a config toggle, fixtures under `tests/fixtures/`,
tests covering hits and non-hits (false-positive guardrails), and a catalog entry.
