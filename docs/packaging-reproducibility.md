# Packaging and reproducibility

PyIsolate now ships a machine-readable installation diagnostic via:

```bash
pyisolate-doctor
```

This command prints JSON that captures Python build provenance, no-GIL status,
kernel feature detection, and hardening fallbacks. Store this artifact in CI and
attach it to release tickets when triaging install issues.

## 1) Exact Python build provenance

`pyisolate-doctor` includes:

- `executable`: resolved Python executable path.
- `executable_sha256`: hash of the interpreter binary.
- `version`, `cache_tag`, `soabi`, `abiflags`.
- `CONFIG_ARGS`, `CFLAGS`, `LDFLAGS` from `sysconfig`.

This is enough to identify *which* interpreter build produced a wheel and whether
it was rebuilt by a downstream packager.

## 2) no-GIL build reproducibility

`hardening.no_gil_runtime.available` is derived from `Py_GIL_DISABLED`.
When false, PyIsolate reports a clear reason and callers can fail closed.

Recommended release check:

```bash
pyisolate-doctor | python -c 'import json,sys; print(json.load(sys.stdin)["hardening"]["no_gil_runtime"])'
```

## 3) Kernel feature detection

`kernel.features` currently probes:

- BPF LSM availability from `/sys/kernel/security/lsm`
- bpffs mount status (`/sys/fs/bpf`)
- cgroup v2 controller support
- io_uring support envelope
- Landlock presence for future fallback paths

All probes include `available` and `reason` fields to avoid ambiguous failures.

## 4) Feature flags for unavailable hardening paths

The report exposes explicit fallback state under `hardening` and `kernel.features`.
If a feature is unavailable, the reason text is intended to be directly shown in
installer output and support dashboards.

## 5) Deterministic wheels and unsupported platforms

Deterministic wheel policy is currently defined for:

- Linux `x86_64`
- Linux `aarch64`

Other targets are reported as unsupported for deterministic guarantees via
`hardening.deterministic_wheels`.

## 6) Signed releases

Use the new release extra to install signing and upload tooling:

```bash
python -m pip install -e .[release]
```

Suggested release flow:

1. Build: `python -m build`
2. Sign: `python -m sigstore sign dist/*`
3. Verify locally: `python -m sigstore verify identity ... dist/*`
4. Upload: `python -m twine upload dist/*`

Persist `pyisolate-doctor` output next to signatures to tie artifacts back to an
exact interpreter + kernel environment.
