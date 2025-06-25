"""ResourceWatchdog stub.

Counts CPU and memory usage for sandboxes. This simplified version only provides
a method to simulate quota checks.
"""


class ResourceWatchdog:
    def check(self, sandbox) -> None:
        # Real implementation would read BPF counters.
        pass
