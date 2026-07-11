"""Backend compatibility helpers for OTLP consumers.

tracewarden emits standard OTel span events, so *any* OTLP backend already
receives the findings. This module adds presentation glue for the two backends
we target explicitly: it mirrors the per-span security summary into the
attribute names Langfuse and Phoenix (OpenInference) surface in their UIs, so
teams can filter/group on security findings there without a custom view.

Nothing here is required for events to arrive — it is optional annotation,
applied by the pipeline on the live span when ``annotate_backends`` is on.
"""

from __future__ import annotations

from collections.abc import Sequence

from opentelemetry.trace import Span

# Langfuse surfaces span attributes as trace metadata; Phoenix/OpenInference
# reads its own namespace. We write both so one span works in either UI.
LANGFUSE_PREFIX = "langfuse.metadata.security"
OPENINFERENCE_PREFIX = "security.summary"

_BACKEND_PREFIXES = (LANGFUSE_PREFIX, OPENINFERENCE_PREFIX)


def annotate_for_backends(
    span: Span,
    *,
    event_count: int,
    max_severity: str,
    event_types: Sequence[str],
) -> None:
    """Mirror the security summary onto the live span under Langfuse/Phoenix names.

    Called by the pipeline right after it sets the canonical ``security.events.*``
    summary attributes, using the same values (no read-back required).
    """
    types = list(event_types)
    for prefix in _BACKEND_PREFIXES:
        span.set_attribute(f"{prefix}.event_count", event_count)
        span.set_attribute(f"{prefix}.max_severity", max_severity)
        span.set_attribute(f"{prefix}.event_types", types)
