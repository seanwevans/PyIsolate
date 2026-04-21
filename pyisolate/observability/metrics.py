"""Prometheus text exporter for supervisor and per-cell metrics."""

from __future__ import annotations

LATENCY_BUCKET_ORDER = ["0.5", "1", "5", "10", "inf"]
_STATE_TO_NUMERIC = {
    "init": 0,
    "bootstrapped": 1,
    "running": 2,
    "hot_reload": 3,
    "quota_exceeded": 4,
    "cancelled": 5,
    "completed": 6,
}


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class MetricsExporter:
    def export(self) -> str:
        from ..supervisor import _get_supervisor

        supervisor = _get_supervisor()
        active = supervisor.list_active()
        health = supervisor.health_snapshot()

        lines: list[str] = []
        described: set[str] = set()

        def emit(name: str, help_text: str, typ: str, sample: str) -> None:
            if name not in described:
                lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} {typ}")
                described.add(name)
            lines.append(sample)

        supervisor_label = _escape_label(str(health["supervisor_id"]))
        emit(
            "pyisolate_supervisor_health",
            "Supervisor health status (1=healthy, 0=unhealthy)",
            "gauge",
            f'pyisolate_supervisor_health{{supervisor_id="{supervisor_label}"}} '
            f'{1 if health["watchdog_alive"] else 0}',
        )

        attachment_status = getattr(supervisor._bpf, "attachment_status", {})
        for program, status in sorted(attachment_status.items()):
            emit(
                "pyisolate_bpf_attachment_status",
                "BPF attachment status by program (1=attached, 0=not attached)",
                "gauge",
                "pyisolate_bpf_attachment_status"
                f'{{supervisor_id="{supervisor_label}",program="{_escape_label(program)}"}} '
                f"{1 if status else 0}",
            )

        for name in sorted(active):
            sb = active[name]
            stats = sb.stats
            sandbox = _escape_label(name)
            cell_id = _escape_label(stats.cell_id)
            labels = f'sandbox="{sandbox}",cell_id="{cell_id}"'
            emit(
                "pyisolate_cell_state",
                "Current cell lifecycle state encoded as numeric value",
                "gauge",
                f"pyisolate_cell_state{{{labels}}} {_STATE_TO_NUMERIC.get(stats.state, -1)}",
            )
            emit(
                "pyisolate_mem_hwm_bytes",
                "Per-cell memory high-water mark in bytes",
                "gauge",
                f"pyisolate_mem_hwm_bytes{{{labels}}} {stats.mem_hwm_bytes}",
            )
            emit(
                "pyisolate_policy_denials_total",
                "Policy denials observed for the cell",
                "counter",
                f"pyisolate_policy_denials_total{{{labels}}} {stats.policy_denials}",
            )
            emit(
                "pyisolate_quota_breaches_total",
                "Quota breach events observed for the cell",
                "counter",
                f"pyisolate_quota_breaches_total{{{labels}}} {stats.quota_breaches}",
            )
            cumul = 0
            sched = stats.scheduler_latency_ms
            for bucket in LATENCY_BUCKET_ORDER:
                if bucket == "inf":
                    count = sched.get("inf", sched.get("+Inf", 0))
                else:
                    count = sched.get(bucket, 0)
                cumul += count
                le = "+Inf" if bucket == "inf" else bucket
                emit(
                    "pyisolate_scheduler_latency_ms",
                    "Scheduler queue latency in milliseconds",
                    "histogram",
                    f'pyisolate_scheduler_latency_ms_bucket{{{labels},le="{le}"}} {cumul}',
                )
            emit(
                "pyisolate_scheduler_latency_ms",
                "Scheduler queue latency in milliseconds",
                "histogram",
                f"pyisolate_scheduler_latency_ms_count{{{labels}}} {stats.operations}",
            )
            emit(
                "pyisolate_scheduler_latency_ms",
                "Scheduler queue latency in milliseconds",
                "histogram",
                f"pyisolate_scheduler_latency_ms_sum{{{labels}}} {stats.scheduler_latency_ms_sum:.3f}",
            )
            emit(
                "pyisolate_kill_latency_ms",
                "Latency to terminate an unresponsive cell in milliseconds",
                "gauge",
                f"pyisolate_kill_latency_ms{{{labels}}} {stats.kill_latency_ms:.3f}",
            )

        return "\n".join(lines) + ("\n" if lines else "")
