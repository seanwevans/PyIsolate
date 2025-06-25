"""Prometheus metrics exporter.

This module exposes :class:`MetricsExporter` which can be used to publish
runtime information about active sandboxes. Metrics are served via the
``/metrics`` HTTP endpoint using :mod:`prometheus_client`.
"""

from __future__ import annotations

from prometheus_client import Gauge, Counter, start_http_server


class MetricsExporter:
    """Collect and expose Prometheus metrics."""

    def __init__(self, supervisor, port: int = 8000) -> None:
        self._supervisor = supervisor
        self._cpu_ms = Gauge(
            "pyisolate_cpu_ms", "CPU time consumed by a sandbox in milliseconds", ["sandbox"]
        )
        self._mem_bytes = Gauge(
            "pyisolate_mem_bytes", "Resident memory usage of a sandbox in bytes", ["sandbox"]
        )
        self._policy_events = Counter(
            "pyisolate_policy_events_total", "Number of policy reload events"
        )
        # Start the HTTP metrics server
        start_http_server(port)

    def export(self) -> None:
        """Update gauge metrics for all active sandboxes."""
        for name, sb in self._supervisor.list_active().items():
            stats = sb.stats
            self._cpu_ms.labels(sandbox=name).set(getattr(stats, "cpu_ms", 0))
            self._mem_bytes.labels(sandbox=name).set(getattr(stats, "mem_bytes", 0))

    def record_policy_reload(self) -> None:
        """Increment the policy reload counter."""
        self._policy_events.inc()
