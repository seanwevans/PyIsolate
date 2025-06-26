"""Simple Prometheus text exporter for sandbox metrics.

The real project would export statistics gathered from eBPF maps.  This
implementation gathers ``SandboxThread.stats`` from the supervisor and formats
them as standard Prometheus ``Gauge`` metrics.  It is intentionally minimal but
useful for tests and examples.
"""


class MetricsExporter:
    def export(self) -> str:
        """Return metrics for all active sandboxes in Prometheus text format."""

        from ..supervisor import list_active

        lines: list[str] = []
        active = list_active()
        for name, sb in active.items():
            stats = sb.stats
            lines.append(f'pyisolate_cpu_ms{{sandbox="{name}"}} {stats.cpu_ms:.0f}')
            lines.append(f'pyisolate_mem_bytes{{sandbox="{name}"}} {stats.mem_bytes}')
            lines.append(
                f'pyisolate_errors_total{{sandbox="{name}"}} {stats.errors}'
            )
            lines.append(f'pyisolate_cost{{sandbox="{name}"}} {stats.cost:.6f}')
            cumul = 0
            for le, count in stats.latency.items():
                cumul += count
                lines.append(
                    f'pyisolate_latency_ms_bucket{{sandbox="{name}",le="{le}"}} {cumul}'
                )
            lines.append(
                f'pyisolate_latency_ms_count{{sandbox="{name}"}} {stats.operations}'
            )
            lines.append(
                f'pyisolate_latency_ms_sum{{sandbox="{name}"}} {stats.latency_sum:.3f}'
            )

        return "\n".join(lines) + ("\n" if lines else "")
