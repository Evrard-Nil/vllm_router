"""
Environment configuration for domain registration.
Handles all environment variable parsing and validation.
"""

import os
import socket
from typing import List, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class DomainRegistrationConfig:
    """Configuration for domain registration loaded from environment variables."""

    enabled: bool
    email: str
    static_ip: str
    cloudflare_api_token: str
    cloudflare_zone_id: Optional[str]
    domains: List[str]
    auto_renew: bool
    renewal_threshold_days: int
    evidence_dir: str
    certificate_dir: str
    attestation_enabled: bool

    @classmethod
    def from_env(cls) -> "DomainRegistrationConfig":
        """Load configuration from environment variables."""
        return cls(
            enabled=os.getenv("DOMAIN_REGISTRATION_ENABLED", "false").lower() == "true",
            email=os.getenv("CERTBOT_EMAIL", ""),
            static_ip=os.getenv("STATIC_IP", ""),
            cloudflare_api_token=os.getenv("CLOUDFLARE_API_TOKEN", ""),
            cloudflare_zone_id=os.getenv("CLOUDFLARE_ZONE_ID"),
            domains=cls._parse_domains(os.getenv("DOMAINS", "")),
            auto_renew=os.getenv("DOMAIN_REGISTRATION_AUTO_RENEW", "true").lower()
            == "true",
            renewal_threshold_days=int(
                os.getenv("DOMAIN_REGISTRATION_RENEWAL_THRESHOLD_DAYS", "30")
            ),
            evidence_dir=os.getenv("DOMAIN_REGISTRATION_EVIDENCE_DIR", "/evidences"),
            certificate_dir=os.getenv(
                "DOMAIN_REGISTRATION_CERTIFICATE_DIR", "/etc/letsencrypt/live"
            ),
            attestation_enabled=os.getenv(
                "DOMAIN_REGISTRATION_ATTESTATION_ENABLED", "true"
            ).lower()
            == "true",
        )

    @staticmethod
    def _parse_domains(domains_str: str) -> List[str]:
        """Parse comma-separated domains from environment variable."""
        if not domains_str:
            return []
        return [domain.strip() for domain in domains_str.split(",") if domain.strip()]

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if not self.enabled:
            return errors

        if not self.email:
            errors.append("CERTBOT_EMAIL environment variable is required")
        elif "@" not in self.email:
            errors.append("CERTBOT_EMAIL must be a valid email address")

        if not self.static_ip:
            errors.append("STATIC_IP environment variable is required")
        else:
            # Validate IP address format
            try:
                socket.inet_aton(self.static_ip)
            except socket.error:
                errors.append(f"STATIC_IP '{self.static_ip}' is not a valid IP address")

        if not self.cloudflare_api_token:
            errors.append("CLOUDFLARE_API_TOKEN environment variable is required")
        elif len(self.cloudflare_api_token) < 10:
            errors.append("CLOUDFLARE_API_TOKEN appears to be invalid (too short)")

        if not self.domains:
            errors.append("DOMAINS environment variable is required")
        else:
            for domain in self.domains:
                if not self._is_valid_domain(domain):
                    errors.append(f"Invalid domain format: {domain}")

        if self.renewal_threshold_days < 1 or self.renewal_threshold_days > 89:
            errors.append(
                "DOMAIN_REGISTRATION_RENEWAL_THRESHOLD_DAYS must be between 1 and 89"
            )

        return errors

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Basic domain validation."""
        if not domain or len(domain) > 253:
            return False

        # Handle wildcard domains
        if domain.startswith("*."):
            domain = domain[2:]

        # Basic domain format check
        parts = domain.split(".")
        if len(parts) < 2:
            return False

        # Check each part
        for part in parts:
            if not part or len(part) > 63:
                return False
            if part.startswith("-") or part.endswith("-"):
                return False

        return True

    def validate_static_ip_matches_machine(self) -> bool:
        """Validate that the configured static IP matches the actual machine IP."""
        try:
            # Get actual IP by connecting to a remote address
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                actual_ip = s.getsockname()[0]

            if self.static_ip != actual_ip:
                logger.warning(
                    f"Configured static IP {self.static_ip} doesn't match actual machine IP {actual_ip}"
                )
                return False

            logger.info(f"Static IP {self.static_ip} validated successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to validate static IP: {e}")
            return False

    def get_domain_list_string(self) -> str:
        """Get domains as a comma-separated string."""
        return ",".join(self.domains)

    def has_wildcard_domains(self) -> bool:
        """Check if any domains are wildcards."""
        return any(domain.startswith("*.") for domain in self.domains)

    def get_base_domains(self) -> List[str]:
        """Get base domains (remove wildcard prefix if present)."""
        base_domains = []
        for domain in self.domains:
            if domain.startswith("*."):
                base_domains.append(domain[2:])
            else:
                base_domains.append(domain)
        return list(set(base_domains))  # Remove duplicates
