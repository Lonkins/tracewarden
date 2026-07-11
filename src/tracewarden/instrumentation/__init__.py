"""Auto-instrumentation adapters. Each one is optional — install the matching
extra (``tracewarden[openai]`` etc.) and call :func:`instrument`."""

from __future__ import annotations

from collections.abc import Callable, Sequence


class MissingDependencyError(RuntimeError):
    def __init__(self, framework: str, extra: str) -> None:
        super().__init__(
            f"Framework {framework!r} is not importable. "
            f'Install the adapter dependencies: pip install "tracewarden[{extra}]"'
        )


def _load(name: str) -> tuple[Callable[[], None], Callable[[], None]]:
    """Return (instrument, uninstrument) for an adapter, importing lazily."""
    match name:
        case "openai":
            from tracewarden.instrumentation import openai_sdk as m1

            return m1.instrument_openai, m1.uninstrument_openai
        case "anthropic":
            from tracewarden.instrumentation import anthropic_sdk as m2

            return m2.instrument_anthropic, m2.uninstrument_anthropic
        case "langchain":
            from tracewarden.instrumentation import langchain as m3

            return m3.instrument_langchain, m3.uninstrument_langchain
        case "llamaindex":
            from tracewarden.instrumentation import llamaindex as m4

            return m4.instrument_llamaindex, m4.uninstrument_llamaindex
        case "pydantic_ai":
            from tracewarden.instrumentation import pydantic_ai as m5

            return m5.instrument_pydantic_ai, m5.uninstrument_pydantic_ai
        case "mcp":
            from tracewarden.instrumentation import mcp_client as m6

            return m6.instrument_mcp, m6.uninstrument_mcp
        case _:
            raise ValueError(f"Unknown framework {name!r}. Known: {sorted(FRAMEWORKS)}")


FRAMEWORKS = frozenset({"openai", "anthropic", "langchain", "llamaindex", "pydantic_ai", "mcp"})

_active: dict[str, Callable[[], None]] = {}


def instrument(frameworks: Sequence[str]) -> list[str]:
    """Instrument the named frameworks. Raises MissingDependencyError if one
    is requested but not importable."""
    done: list[str] = []
    for name in frameworks:
        if name in _active:
            done.append(name)
            continue
        install_fn, uninstall_fn = _load(name)
        install_fn()
        _active[name] = uninstall_fn
        done.append(name)
    return done


def uninstrument_all() -> None:
    for uninstall_fn in _active.values():
        uninstall_fn()
    _active.clear()
