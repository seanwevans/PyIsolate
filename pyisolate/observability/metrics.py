"""Simple Prometheus text exporter for sandbox metrics.

The real project would export statistics gathered from eBPF maps.  This
implementation gathers ``SandboxThread.stats`` from the supervisor and formats
them as standard Prometheus ``Gauge`` metrics.  It is intentionally minimal but
useful for tests and examples.
"""


def _escape_label(value: str) -> str:
    """Escape a label value according to the Prometheus text exposition format.

    Prometheus expects backslashes, double quotes and newlines within label
    values to be escaped.  This helper normalizes sandbox names so that they
    remain valid even if they contain such characters.
    """

    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class MetricsExporter:
    def export(self) -> str:
        """Return metrics for all active sandboxes in Prometheus text format."""

        from ..supervisor import list_active

        lines: list[str] = []
        described: set[str] = set()

        def emit(name: str, help_text: str, typ: str, sample: str) -> None:
            if name not in described:
                lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} {typ}")
                described.add(name)
            lines.append(sample)

        active = list_active()
        for name in sorted(active):
            sb = active[name]
            stats = sb.stats
            label = _escape_label(name)
            emit(
                "pyisolate_cpu_ms",
                "CPU time consumed by sandbox in milliseconds",
                "gauge",
                f'pyisolate_cpu_ms{{sandbox="{label}"}} {stats.cpu_ms:.0f}',
            )
            emit(
                "pyisolate_mem_bytes",
                "Resident memory used by sandbox in bytes",
                "gauge",
                f'pyisolate_mem_bytes{{sandbox="{label}"}} {stats.mem_bytes}',
            )
            emit(
                "pyisolate_errors_total",
                "Total errors encountered by sandbox",
                "counter",
                f'pyisolate_errors_total{{sandbox="{label}"}} {stats.errors}',
            )
            emit(
                "pyisolate_cost",
                "Internal cost score for sandbox",
                "gauge",
                f'pyisolate_cost{{sandbox="{label}"}} {stats.cost:.6f}',
            )
            cumul = 0
            for le, count in stats.latency.items():
                cumul += count
                emit(
                    "pyisolate_latency_ms",
                    "Sandbox operation latency in milliseconds",
                    "histogram",
                    f'pyisolate_latency_ms_bucket{{sandbox="{label}",le="{le}"}} {cumul}',
                )
            emit(
                "pyisolate_latency_ms",
                "Sandbox operation latency in milliseconds",
                "histogram",
                f'pyisolate_latency_ms_count{{sandbox="{label}"}} {stats.operations}',
            )
            emit(
                "pyisolate_latency_ms",
                "Sandbox operation latency in milliseconds",
                "histogram",
                f'pyisolate_latency_ms_sum{{sandbox="{label}"}} {stats.latency_sum:.3f}',
            )

        return "\n".join(lines) + ("\n" if lines else "")
