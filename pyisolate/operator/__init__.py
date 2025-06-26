"""Kubernetes operator for PyIsolate sandboxes."""
from __future__ import annotations

__all__ = ["run_operator", "scale_sandboxes"]


def run_operator(namespace: str = "default") -> None:
    """Start the operator watch loop."""
    from kubernetes import client, config, watch  # type: ignore

    config.load_incluster_config()
    api = client.CustomObjectsApi()
    w = watch.Watch()
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
        # TODO: integrate with supervisor to schedule sandbox
        print(f"received {op} for sandbox {name}")


def scale_sandboxes(target: int) -> None:
    """Scale the number of running sandbox pods."""
    # Placeholder for future auto-scaling logic
    print(f"scaling sandboxes to {target}")
