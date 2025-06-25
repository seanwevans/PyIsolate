"""CryptoBroker stub.

This module would normally handle AEAD framing and counters. In this skeleton it
only passes data through unchanged.
"""


class CryptoBroker:
    """Simplified crypto broker."""

    def frame(self, data: bytes) -> bytes:
        return data

    def unframe(self, data: bytes) -> bytes:
        return data
