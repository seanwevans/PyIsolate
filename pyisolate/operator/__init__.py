"""Kubernetes operator for PyIsolate sandboxes."""
from __future__ import annotations

import logging
from typing import Dict

from ..supervisor import Supervisor

__all__ = ["run_operator", "scale_sandboxes"]

logger = logging.getLogger(__name__)


def run_operator(namespace: str = "default") -> None:
    """Start the operator watch loop."""
    from kubernetes import client, config, watch  # type: ignore

    config.load_incluster_config()
    api = client.CustomObjectsApi()
    w = watch.Watch()
    sup = Supervisor()
    sandboxes: Dict[str, object] = {}
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
            if op == "ADDED":
                sandboxes[name] = sup.spawn(name)
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
