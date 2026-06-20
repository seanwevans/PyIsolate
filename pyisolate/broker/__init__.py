"""Broker package: authenticated, length-framed channels for sandbox IPC.

The public names are imported lazily (PEP 562) so that merely importing
``pyisolate.broker`` does not eagerly require the optional ``cryptography``
dependency; it is only imported when one of the crypto/channel names is first
accessed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = [
    "CryptoBroker",
    "SecureChannel",
    "handshake",
    "secure_channel_pair",
]

if TYPE_CHECKING:  # pragma: no cover - import hints for type checkers only
    from .channel import SecureChannel, secure_channel_pair
    from .crypto import CryptoBroker, handshake


def __getattr__(name: str):
    if name in {"CryptoBroker", "handshake"}:
        from . import crypto

        return getattr(crypto, name)
    if name in {"SecureChannel", "secure_channel_pair"}:
        from . import channel

        return getattr(channel, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
