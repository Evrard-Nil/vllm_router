"""
Simplified quote module for testing signing functionality without heavy dependencies.
"""

import json
import os
from hashlib import sha256
from typing import Optional

ED25519 = "ed25519"
ECDSA = "ecdsa"


class SimpleSigningContext:
    """Simple signing context for testing."""

    def __init__(self, method: str):
        self.method = method
        # Generate a simple deterministic signing address for testing
        self.signing_address = self._generate_test_address()

    def _generate_test_address(self) -> str:
        """Generate a deterministic test address."""
        if self.method == ECDSA:
            # Simple Ethereum-style address
            return "0x" + sha256(f"ecdsa_test_{os.getpid()}".encode()).hexdigest()[:40]
        else:
            # Simple ED25519-style address (64 bytes = 128 hex chars)
            # Generate 64 bytes of data and convert to hex
            hash_data = sha256(f"ed25519_test_{os.getpid()}".encode()).hexdigest()
            # Double the hash to get 64 bytes (128 hex chars)
            return (hash_data + hash_data)[:128]

    def sign(self, content: str) -> str:
        """Simple signing implementation for testing."""
        if self.method == ECDSA:
            # Simple ECDSA-style signature (starts with 0x)
            return (
                "0x"
                + sha256(
                    f"ecdsa_sig_{content}_{self.signing_address}".encode()
                ).hexdigest()
            )
        else:
            # Simple ED25519-style signature (hex string)
            return sha256(
                f"ed25519_sig_{content}_{self.signing_address}".encode()
            ).hexdigest()


# Create test contexts
ecdsa_context = SimpleSigningContext(ECDSA)
ed25519_context = SimpleSigningContext(ED25519)


def sign_message(context: SimpleSigningContext, content: str) -> str:
    """Sign a message using the given context."""
    return context.sign(content)


def sign_chat(text: str) -> dict:
    """
    Create a signed chat data structure with both ECDSA and ED25519 signatures.

    Args:
        text: The text to sign (typically request_hash:response_hash)

    Returns:
        Dictionary containing both signatures and their corresponding signing addresses
    """
    return dict(
        text=text,
        signature_ecdsa=sign_message(ecdsa_context, text),
        signing_address_ecdsa=ecdsa_context.signing_address,
        signature_ed25519=sign_message(ed25519_context, text),
        signing_address_ed25519=ed25519_context.signing_address,
    )


def generate_attestation(
    context: SimpleSigningContext, nonce: Optional[bytes | str] = None
) -> dict:
    """
    Generate a simple attestation for testing.

    This is a simplified version that doesn't require heavy dependencies.
    """
    # Simple nonce handling
    if nonce is None:
        nonce = sha256(os.urandom(32)).hexdigest()
    elif isinstance(nonce, bytes):
        nonce = nonce.hex()

    return dict(
        signing_address=context.signing_address,
        signing_algo=context.method,
        request_nonce=nonce,
        intel_quote="mock_intel_quote",
        nvidia_payload="mock_nvidia_payload",
        event_log={"mock": "event"},
        info={"mock": "attestation_info"},
    )


__all__ = [
    "SimpleSigningContext",
    "sign_message",
    "sign_chat",
    "generate_attestation",
    "ecdsa_context",
    "ed25519_context",
    "ED25519",
    "ECDSA",
]
