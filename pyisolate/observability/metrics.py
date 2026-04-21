"""Simple Prometheus text exporter for sandbox metrics.

The real project would export statistics gathered from eBPF maps.  This
implementation gathers ``SandboxThread.stats`` from the supervisor and formats
them as standard Prometheus ``Gauge`` metrics.  It is intentionally minimal but
useful for tests and examples.
"""

LATENCY_BUCKET_ORDER = ["0.5", "1", "5", "10", "inf"]


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

        from ..supervisor import _get_supervisor, list_active

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
            cell_id = _escape_label(stats.cell_id)
            emit(
                "pyisolate_cpu_ms",
                "CPU time consumed by sandbox in milliseconds",
                "gauge",
                f'pyisolate_cpu_ms{{sandbox="{label}",cell_id="{cell_id}"}} {stats.cpu_ms:.0f}',
            )
            emit(
                "pyisolate_mem_bytes",
                "Resident memory used by sandbox in bytes",
                "gauge",
                f'pyisolate_mem_bytes{{sandbox="{label}",cell_id="{cell_id}"}} {stats.mem_bytes}',
            )
            emit(
                "pyisolate_mem_hwm_bytes",
                "High-water resident memory used by sandbox in bytes",
                "gauge",
                f'pyisolate_mem_hwm_bytes{{sandbox="{label}",cell_id="{cell_id}"}} {stats.mem_hwm_bytes}',
            )
            emit(
                "pyisolate_errors_total",
                "Total errors encountered by sandbox",
                "counter",
                f'pyisolate_errors_total{{sandbox="{label}",cell_id="{cell_id}"}} {stats.errors}',
            )
            emit(
                "pyisolate_cost",
                "Internal cost score for sandbox",
                "gauge",
                f'pyisolate_cost{{sandbox="{label}",cell_id="{cell_id}"}} {stats.cost:.6f}',
            )
            emit(
                "pyisolate_cell_state",
                "Current cell lifecycle state (one sample per active cell)",
                "gauge",
                f'pyisolate_cell_state{{sandbox="{label}",cell_id="{cell_id}",state="{_escape_label(stats.state)}",start_reason="{_escape_label(stats.start_reason)}",stop_reason="{_escape_label(stats.stop_reason or "running")}"}} 1',
            )
            emit(
                "pyisolate_policy_denials_total",
                "Total policy denial exceptions raised by sandbox",
                "counter",
                f'pyisolate_policy_denials_total{{sandbox="{label}",cell_id="{cell_id}"}} {stats.policy_denials}',
            )
            for breach_kind, breach_count in sorted(stats.quota_breaches.items()):
                emit(
                    "pyisolate_quota_breaches_total",
                    "Total quota breaches detected for sandbox",
                    "counter",
                    f'pyisolate_quota_breaches_total{{sandbox="{label}",cell_id="{cell_id}",kind="{_escape_label(breach_kind)}"}} {breach_count}',
                )
            emit(
                "pyisolate_scheduler_latency_ms",
                "Queueing latency between operation enqueue and execution",
                "summary",
                f'pyisolate_scheduler_latency_ms_sum{{sandbox="{label}",cell_id="{cell_id}"}} {stats.scheduler_latency_ms_sum:.3f}',
            )
            emit(
                "pyisolate_scheduler_latency_ms",
                "Queueing latency between operation enqueue and execution",
                "summary",
                f'pyisolate_scheduler_latency_ms_count{{sandbox="{label}",cell_id="{cell_id}"}} {stats.scheduler_latency_samples}',
            )
            emit(
                "pyisolate_kill_latency_ms",
                "Latency between kill request and thread join completion",
                "gauge",
                f'pyisolate_kill_latency_ms{{sandbox="{label}",cell_id="{cell_id}"}} {stats.kill_latency_ms:.3f}',
            )
            cumul = 0
            for bucket in LATENCY_BUCKET_ORDER:
                if bucket == "inf":
                    count = stats.latency.get("inf", stats.latency.get("+Inf", 0))
                else:
                    count = stats.latency.get(bucket, 0)
                cumul += count
                # Emit Prometheus canonical +Inf label while still accepting
                # either "inf" (legacy/internal) or "+Inf" in source stats.
                le = "+Inf" if bucket == "inf" else bucket
                emit(
                    "pyisolate_latency_ms",
                    "Sandbox operation latency in milliseconds",
                    "histogram",
                    f'pyisolate_latency_ms_bucket{{sandbox="{label}",cell_id="{cell_id}",le="{le}"}} {cumul}',
                )
            emit(
                "pyisolate_latency_ms",
                "Sandbox operation latency in milliseconds",
                "histogram",
                f'pyisolate_latency_ms_count{{sandbox="{label}",cell_id="{cell_id}"}} {stats.operations}',
            )
            emit(
                "pyisolate_latency_ms",
                "Sandbox operation latency in milliseconds",
                "histogram",
                f'pyisolate_latency_ms_sum{{sandbox="{label}",cell_id="{cell_id}"}} {stats.latency_sum:.3f}',
            )

        sup = _get_supervisor()
        health = sup.health_snapshot()
        emit(
            "pyisolate_supervisor_health",
            "Supervisor health status",
            "gauge",
            f'pyisolate_supervisor_health{{supervisor_id="{_escape_label(str(health["supervisor_id"]))}"}} {health["healthy"]}',
        )
        attachment_status = getattr(sup._bpf, "attachment_status", {})
        if not attachment_status:
            attachment_status = {"unknown": False}
        for prog, attached in sorted(attachment_status.items()):
            emit(
                "pyisolate_bpf_attachment_status",
                "BPF program attachment status",
                "gauge",
                f'pyisolate_bpf_attachment_status{{supervisor_id="{_escape_label(str(health["supervisor_id"]))}",program="{_escape_label(prog)}"}} {1 if attached else 0}',
            )

        return "\n".join(lines) + ("\n" if lines else "")
