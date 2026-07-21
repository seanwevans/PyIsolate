"""Kubernetes operator for PyIsolate sandboxes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict

from ..supervisor import Supervisor

if TYPE_CHECKING:
    from ..supervisor import Sandbox

__all__ = ["run_operator", "scale_sandboxes"]

logger = logging.getLogger(__name__)


def run_operator(namespace: str = "default") -> None:
    """Start the operator watch loop.

    Requires the optional ``kubernetes`` client, which is not a core dependency.
    Install it with ``pip install pyisolate[operator]``.
    """
    try:
        from kubernetes import client, config, watch  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "the PyIsolate Kubernetes operator requires the 'kubernetes' "
            "package, which is not installed. Install it with "
            "`pip install pyisolate[operator]`."
        ) from exc

    config.load_incluster_config()
    api = client.CustomObjectsApi()
    w = watch.Watch()
    sup = Supervisor()
    sandboxes: Dict[str, "Sandbox"] = {}
    for event in w.stream(
        api.list_namespaced_custom_object,
        group="pyisolate.dev",
        version="v1",
        namespace=namespace,
        plural="pyisolates",
    ):
        obj = event["object"]
        op = event["type"]
        name = obj["metadata"]["name"]
        logger.info("received %s for sandbox %s", op, name)
        try:
            if op in ("ADDED", "MODIFIED"):
                existing = sandboxes.get(name)
                if existing is None:
                    # New object, or a watch relist re-announcing one we do not
                    # track yet.
                    sandboxes[name] = sup.spawn(name)
                elif op == "MODIFIED":
                    # Reconcile a spec change by replacing the sandbox.
                    existing.close()
                    sandboxes[name] = sup.spawn(name)
                # A re-delivered ADDED for a sandbox we already run is a no-op;
                # Kubernetes relists re-send every object as ADDED, and spawning
                # again would raise "already exists".
            elif op == "DELETED":
                sb = sandboxes.pop(name, None)
                if sb:
                    sb.close()
        except Exception as exc:  # pragma: no cover - logging path
            logger.error("failed to handle %s for %s: %s", op, name, exc)


def scale_sandboxes(target: int) -> None:
    """Scale the number of running sandbox pods."""
    # Placeholder for future auto-scaling logic
    print(f"scaling sandboxes to {target}")
