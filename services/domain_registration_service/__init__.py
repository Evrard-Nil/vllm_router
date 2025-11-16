"""
Domain registration service for vLLM router.
Integrates certificate management, DNS operations, and TLS attestation.
"""

from .domain_service import DomainRegistrationService, get_domain_registration_service

__all__ = [
    "DomainRegistrationService",
    "get_domain_registration_service",
]
