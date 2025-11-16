"""
Cloudflare DNS provider for domain registration.
Handles DNS record management for Let's Encrypt DNS-01 challenges.
"""

import logging
import time
from typing import List, Optional, Dict, Any
from cloudflare import Cloudflare
from cloudflare.types.zone import Zone
from cloudflare.types.dns_record import ARecord, CaaRecord, DnsRecord

logger = logging.getLogger(__name__)


class CloudflareDNSProvider:
    """Cloudflare DNS provider for managing A and CAA records."""

    def __init__(self, api_token: str, zone_id: Optional[str] = None):
        """
        Initialize Cloudflare DNS provider.

        Args:
            api_token: Cloudflare API token
            zone_id: Optional zone ID (auto-detected if not provided)
        """
        self.api_token = api_token
        self.zone_id = zone_id
        self.client = Cloudflare(api_token=api_token)
        self._zone_cache: Dict[str, str] = {}

    def validate_credentials(self) -> bool:
        """Validate Cloudflare API token."""
        try:
            # Test the API token by getting user info
            self.client.user.tokens.verify()
            logger.info("Cloudflare API token validation successful")
            return True
        except Exception as e:
            logger.error(f"Cloudflare API token validation failed: {e}")
            return False

    def get_zone_id(self, domain: str) -> str:
        """
        Get zone ID for domain, auto-detect if not provided.

        Args:
            domain: Domain name

        Returns:
            Zone ID

        Raises:
            ValueError: If zone not found
        """
        if self.zone_id:
            logger.debug(f"Using configured zone ID: {self.zone_id}")
            return self.zone_id

        # Check cache first
        if domain in self._zone_cache:
            logger.debug(
                f"Using cached zone ID for {domain}: {self._zone_cache[domain]}"
            )
            return self._zone_cache[domain]

        # Extract zone name from domain
        zone_name = self._extract_zone_name(domain)
        logger.debug(f"Looking up zone for domain {domain} (zone: {zone_name})")

        try:
            zones = self.client.zones.list(name=zone_name)
            if not zones:
                raise ValueError(
                    f"Zone not found for domain: {domain} (tried zone: {zone_name})"
                )

            zone_id = zones[0].id
            self._zone_cache[domain] = zone_id
            logger.info(f"Found zone ID {zone_id} for domain {domain}")
            return zone_id

        except Exception as e:
            logger.error(f"Failed to get zone ID for {domain}: {e}")
            raise ValueError(f"Zone not found for domain: {domain}") from e

    def _extract_zone_name(self, domain: str) -> str:
        """Extract zone name from domain (remove subdomains)."""
        # Handle wildcard domains
        if domain.startswith("*."):
            domain = domain[2:]

        # For now, assume the domain itself is the zone
        # In a more complex implementation, we might need to try different levels
        parts = domain.split(".")
        if len(parts) >= 2:
            # Return the last two parts as the zone (e.g., example.com)
            return ".".join(parts[-2:])
        return domain

    def _get_record_name(self, domain: str, zone_id: str) -> str:
        """Get DNS record name relative to zone."""
        zone_name = self._get_zone_name_by_id(zone_id)
        if domain == zone_name:
            return "@"  # Root domain
        elif domain.endswith("." + zone_name):
            return domain[: -len("." + zone_name)]
        else:
            return domain

    def _get_zone_name_by_id(self, zone_id: str) -> str:
        """Get zone name by zone ID."""
        try:
            zone = self.client.zones.get(zone_id)
            return zone.name
        except Exception as e:
            logger.error(f"Failed to get zone name for ID {zone_id}: {e}")
            return ""

    def set_a_record(self, domain: str, ip_address: str, ttl: int = 60) -> bool:
        """
        Create or update A record for domain.

        Args:
            domain: Domain name
            ip_address: IP address for A record
            ttl: TTL for the record

        Returns:
            True if successful
        """
        try:
            zone_id = self.get_zone_id(domain)
            record_name = self._get_record_name(domain, zone_id)

            logger.info(
                f"Setting A record for {domain} (zone: {zone_id}, record: {record_name}) -> {ip_address}"
            )

            # Delete existing A records for this name
            self._delete_existing_records(zone_id, record_name, "A")

            # Create new A record
            record_data = {
                "name": record_name,
                "type": "A",
                "content": ip_address,
                "ttl": ttl,
            }

            result = self.client.dns.records.create(zone_id=zone_id, **record_data)
            logger.info(f"Created A record {result.id} for {domain}")
            return True

        except Exception as e:
            logger.error(f"Failed to create A record for {domain}: {e}")
            return False

    def set_caa_record(self, domain: str, ttl: int = 60) -> bool:
        """
        Create CAA record for Let's Encrypt.

        Args:
            domain: Domain name
            ttl: TTL for the record

        Returns:
            True if successful
        """
        try:
            zone_id = self.get_zone_id(domain)
            record_name = self._get_record_name(domain, zone_id)

            logger.info(
                f"Setting CAA record for {domain} (zone: {zone_id}, record: {record_name})"
            )

            # Delete existing CAA records for this name
            self._delete_existing_records(zone_id, record_name, "CAA")

            # Create CAA record for Let's Encrypt
            record_data = {
                "name": record_name,
                "type": "CAA",
                "data": {"tag": "issue", "value": "letsencrypt.org"},
                "ttl": ttl,
            }

            result = self.client.dns.records.create(zone_id=zone_id, **record_data)
            logger.info(f"Created CAA record {result.id} for {domain}")
            return True

        except Exception as e:
            logger.error(f"Failed to create CAA record for {domain}: {e}")
            return False

    def _delete_existing_records(
        self, zone_id: str, record_name: str, record_type: str
    ) -> None:
        """Delete existing records of specified type and name."""
        try:
            # List existing records
            records = self.client.dns.records.list(
                zone_id=zone_id, name=record_name, type=record_type
            )

            # Delete each record
            for record in records:
                logger.debug(
                    f"Deleting existing {record_type} record {record.id} for {record_name}"
                )
                self.client.dns.records.delete(record.id)

        except Exception as e:
            logger.warning(
                f"Failed to delete existing {record_type} records for {record_name}: {e}"
            )

    def get_dns_records(
        self, domain: str, record_type: Optional[str] = None
    ) -> List[DnsRecord]:
        """
        Get DNS records for a domain.

        Args:
            domain: Domain name
            record_type: Optional record type filter

        Returns:
            List of DNS records
        """
        try:
            zone_id = self.get_zone_id(domain)
            record_name = self._get_record_name(domain, zone_id)

            params = {
                "zone_id": zone_id,
                "name": record_name,
            }
            if record_type:
                params["type"] = record_type

            records = self.client.dns.records.list(**params)
            return list(records)

        except Exception as e:
            logger.error(f"Failed to get DNS records for {domain}: {e}")
            return []

    def verify_dns_propagation(
        self,
        domain: str,
        expected_content: str,
        record_type: str = "A",
        timeout: int = 300,
    ) -> bool:
        """
        Wait for DNS propagation and verify record content.

        Args:
            domain: Domain name
            expected_content: Expected record content
            record_type: Record type to check
            timeout: Maximum time to wait in seconds

        Returns:
            True if record propagates with expected content
        """
        import dns.resolver

        logger.info(f"Waiting for DNS propagation for {domain} {record_type} record")
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for answer in answers:
                    if str(answer) == expected_content:
                        logger.info(f"DNS propagation confirmed for {domain}")
                        return True
                    logger.debug(
                        f"Found {record_type} record for {domain}: {answer} (expected: {expected_content})"
                    )

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                logger.debug(f"DNS record not yet propagated for {domain}")

            time.sleep(10)  # Wait 10 seconds before retrying

        logger.warning(f"DNS propagation timeout for {domain} after {timeout} seconds")
        return False

    def cleanup_dns_records(self, domain: str) -> bool:
        """
        Clean up DNS records for a domain (useful for testing).

        Args:
            domain: Domain name

        Returns:
            True if successful
        """
        try:
            zone_id = self.get_zone_id(domain)
            record_name = self._get_record_name(domain, zone_id)

            # Delete A and CAA records
            self._delete_existing_records(zone_id, record_name, "A")
            self._delete_existing_records(zone_id, record_name, "CAA")

            logger.info(f"Cleaned up DNS records for {domain}")
            return True

        except Exception as e:
            logger.error(f"Failed to cleanup DNS records for {domain}: {e}")
            return False
