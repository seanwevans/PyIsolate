from __future__ import annotations

from contextlib import contextmanager, nullcontext

try:
    from opentelemetry import trace as _otel_trace
except Exception:  # pragma: no cover - optional dep
    _otel_trace = None


class Tracer:
    """Light wrapper around OpenTelemetry tracer."""

    def __init__(self, name: str = "pyisolate") -> None:
        self._tracer = _otel_trace.get_tracer(name) if _otel_trace else None

    @contextmanager
    def start_span(self, name: str):
        if self._tracer:
            with self._tracer.start_as_current_span(name):
                yield
        else:
            with nullcontext():
                yield
