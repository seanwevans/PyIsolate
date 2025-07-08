"""Simple visual policy editor and debugger.

Pass a token to :class:`PolicyEditor` or :meth:`reload` to authenticate hot
reloads against the running supervisor.
"""

from __future__ import annotations

import fnmatch
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

from .policy import refresh
from .policy import yaml as policy_yaml

# ---------- Parsing helpers ----------


def parse_policy(text: str) -> dict:
    """Return the policy dictionary represented by *text*."""
    return policy_yaml.safe_load(text)


def check_fs(policy: dict, path: str, write: bool = False) -> bool:
    """Return ``True`` if ``path`` is allowed under ``policy``."""
    fs = policy.get("fs")
    if fs == "readonly":
        return not write
    if fs == "none":
        return False
    if isinstance(fs, list):
        for rule in fs:
            if "allow" in rule and fnmatch.fnmatch(path, rule["allow"]):
                return True
            if "deny" in rule and fnmatch.fnmatch(path, rule["deny"]):
                return False
    return False


def check_tcp(policy: dict, addr: str) -> bool:
    """Return ``True`` if ``addr`` can be connected to under ``policy``."""
    net = policy.get("net")
    if net == "none":
        return False
    if isinstance(net, list):
        for rule in net:
            if "connect" in rule and fnmatch.fnmatch(addr, rule["connect"]):
                return True
            if "deny" in rule and fnmatch.fnmatch(addr, rule["deny"]):
                return False
    return False


# ---------- Tkinter UI ----------


class PolicyEditor(tk.Tk):
    """Minimal Tk-based policy editor and debugger."""

    def __init__(self, path: str | None = None, token: str | None = None):
        super().__init__()
        self.title("PyIsolate Policy Editor")
        self.geometry("600x400")
        self.path = Path(path).resolve() if path else None
        self.token = token

        self.text = tk.Text(self, wrap="none")
        self.text.pack(fill=tk.BOTH, expand=True)

        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X)
        tk.Button(btn_frame, text="Open", command=self.open_file).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Save", command=self.save_file).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Validate", command=self.validate).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Reload", command=self.reload).pack(side=tk.LEFT)

        dbg = tk.Frame(self)
        dbg.pack(fill=tk.X)
        tk.Label(dbg, text="Test path/addr:").pack(side=tk.LEFT)
        self.test_entry = tk.Entry(dbg)
        self.test_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(dbg, text="Check", command=self.check).pack(side=tk.LEFT)

        if self.path and self.path.exists():
            self.load_file(self.path)

    # file operations
    def load_file(self, path: Path) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            self.text.delete("1.0", tk.END)
            self.text.insert("1.0", fh.read())
        self.path = path

    def open_file(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("YAML", "*.yml *.yaml")])
        if filename:
            self.load_file(Path(filename))

    def save_file(self) -> None:
        if self.path is None:
            filename = filedialog.asksaveasfilename(defaultextension=".yaml")
            if not filename:
                return
            self.path = Path(filename)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(self.text.get("1.0", tk.END))
        messagebox.showinfo("Saved", str(self.path))

    # policy actions
    def validate(self) -> None:
        try:
            parse_policy(self.text.get("1.0", tk.END))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Invalid", str(exc))
        else:
            messagebox.showinfo("Valid", "Policy OK")

    def reload(self, token: str | None = None) -> None:
        """Write edits to disk and hot-reload the policy."""

        if self.path is None:
            messagebox.showerror("Error", "No policy file loaded")
            return

        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(self.text.get("1.0", tk.END))

        tok = token or self.token
        if tok is None:
            tok = simpledialog.askstring("Token", "Policy token:", show="*")
            if tok is None:
                return
            self.token = tok

        try:
            refresh(str(self.path), token=tok)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Reload failed", str(exc))
        else:
            messagebox.showinfo("Reloaded", "Policy hotloaded")

    def check(self) -> None:
        query = self.test_entry.get().strip()
        if not query:
            return
        try:
            policy = parse_policy(self.text.get("1.0", tk.END))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Invalid policy", str(exc))
            return
        if ":" in query:
            allowed = check_tcp(policy, query)
            msg = f"net {query}: {'allowed' if allowed else 'denied'}"
        else:
            allowed = check_fs(policy, query)
            msg = f"fs {query}: {'allowed' if allowed else 'denied'}"
        messagebox.showinfo("Debug", msg)


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else None
    editor = PolicyEditor(path)
    editor.mainloop()


if __name__ == "__main__":  # pragma: no cover - manual invocation
    main()
