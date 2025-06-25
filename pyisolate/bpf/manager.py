"""BPFManager stub.

In a full implementation this module would compile and manage eBPF programs.
Here it only provides placeholders required by the supervisor.
"""


class BPFManager:
    """Placeholder for eBPF compilation and attachment logic."""

    def __init__(self):
        self.loaded = False

    def load(self):
        self.loaded = True

    def hot_reload(self, policy_path: str) -> None:
        if not self.loaded:
            raise RuntimeError("BPF not loaded")
        # noop in stub
