# Kubernetes Operator

This guide describes how to run PyIsolate sandboxes on a Kubernetes cluster.

## Container Image

A sample `Dockerfile` is provided in the repository root. It installs `clang`,
`llvm` and `bpftool` so that eBPF programs can be compiled and loaded at
runtime.

Build the image with:

```bash
docker build -t pyisolate:latest .
```

## Operator

`pyisolate.operator` contains a minimal operator written with the Kubernetes
Python client. The operator watches the `PyIsolateSandbox` custom resource and
spawns supervisor pods for each instance.

### Auto-scaling

Sandbox resource metrics are exposed as custom metrics. A `HorizontalPodAutoscaler`
can consume these metrics to scale the number of sandbox pods according to CPU
or memory load.

### Multi-tenant isolation

Each tenant receives its own Kubernetes namespace and corresponding sandbox
policy. This keeps resources and policies isolated between tenants.
