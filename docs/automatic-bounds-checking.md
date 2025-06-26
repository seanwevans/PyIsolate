# Automatic bounds checking insertion

Automatic bounds checking refers to a compilation or instrumentation step that inserts range checks before each memory access. The goal is to prevent out‑of‑bounds reads and writes, which can lead to undefined behaviour or security issues.

A compiler that inserts bounds checks might transform

```c
value = arr[i];
```
into
```c
if (i >= 0 && i < array_length) {
    value = arr[i];
} else {
    handle_bounds_error();
}
```

High‑level languages like Rust or Go perform these checks automatically. In C/C++ it can be enabled via sanitizers (for example Clang’s AddressSanitizer). Such tools instrument every memory access so that invalid indexes trigger traps or exceptions at runtime.

