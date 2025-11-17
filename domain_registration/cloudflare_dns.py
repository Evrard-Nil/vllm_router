"""
Cloudflare DNS provider for domain registration.
Handles DNS record management for Let's Encrypt DNS-01 challenges.
"""

import json
import logging
import sys
import time
from typing import List, Optional, Dict, Any

import requests

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
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        self.zone_id = zone_id
        self.zone_domain: Optional[str] = None  # Cache the domain for the zone
        self._zone_cache: Dict[str, str] = {}

    def _make_request(
        self, method: str, endpoint: str, data: Optional[Dict] = None
    ) -> Dict:
        """Make a request to the Cloudflare API with error handling."""
        url = f"{self.base_url}/{endpoint}"
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=self.headers)
            elif method.upper() == "POST":
                response = requests.post(url, headers=self.headers, json=data)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=self.headers)
            elif method.upper() == "PUT":
                response = requests.put(url, headers=self.headers, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            result = response.json()

            if not result.get("success", False):
                errors = result.get("errors", [])
                error_msg = "\n".join(
                    [
                        f"Code: {e.get('code')}, Message: {e.get('message')}"
                        for e in errors
                    ]
                )
                logger.error(f"API Error: {error_msg}")
                if data:
                    logger.debug(f"Request data: {json.dumps(data)}")
                return {"success": False, "errors": errors}

            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"Request Error: {str(e)}")
            if data:
                logger.debug(f"Request data: {json.dumps(data)}")
            return {"success": False, "errors": [{"message": str(e)}]}
        except json.JSONDecodeError:
            logger.error("JSON Decode Error: Could not parse response")
            return {
                "success": False,
                "errors": [{"message": "Could not parse response"}],
            }
        except Exception as e:
            logger.error(f"Unexpected Error: {str(e)}")
            return {"success": False, "errors": [{"message": str(e)}]}

    def validate_credentials(self) -> bool:
        """Validate Cloudflare API token."""
        try:
            # Test the API token by verifying it
            result = self._make_request("GET", "user/tokens/verify")
            if result.get("success", False):
                logger.info("Cloudflare API token validation successful")
                return True
            else:
                logger.error("Cloudflare API token validation failed")
                return False
        except Exception as e:
            logger.error(f"Cloudflare API token validation failed: {e}")
            return False

    def _get_zone_info(self, domain: str) -> Optional[tuple[str, str]]:
        """Get the zone ID and zone name for a domain with pagination support."""
        zone_name_len = 0
        zone_id = None
        zone_name_found = None

        page = 1
        total_pages = 1

        while page <= total_pages:
            result = self._make_request("GET", f"zones?page={page}")

            if not result.get("success", False):
                return None

            zones = result.get("result", [])
            if not zones and page == 1:
                logger.error("No zones found for any domain")
                return None

            result_info = result.get("result_info", {})
            if result_info:
                total_pages = result_info.get("total_pages", total_pages)

            for zone in zones:
                zone_name = zone.get("name", "")
                # Exact match - return immediately
                if domain == zone_name:
                    return (zone.get("id"), zone_name)
                # Subdomain match - keep track of longest match
                if domain.endswith(f".{zone_name}") and len(zone_name) > zone_name_len:
                    zone_name_len = len(zone_name)
                    zone_id = zone.get("id")
                    zone_name_found = zone_name

            page += 1

        if zone_id and zone_name_found:
            return (zone_id, zone_name_found)
        else:
            logger.error(f"Zone ID not found in response for domain: {domain}")
            return None

    def _ensure_zone_id(self, domain: str) -> Optional[str]:
        """Ensure we have a zone ID for the domain, fetching if necessary."""
        # If we have a cached zone that matches this domain, use it
        if self.zone_id and self.zone_domain:
            if domain == self.zone_domain or domain.endswith(f".{self.zone_domain}"):
                return self.zone_id

        # Otherwise, fetch zone info
        zone_info = self._get_zone_info(domain)
        if zone_info:
            self.zone_id, self.zone_domain = zone_info
            logger.info(f"Found zone ID {self.zone_id} for domain {domain} (zone: {self.zone_domain})")
        return self.zone_id

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
        zone_id = self._ensure_zone_id(domain)
        if not zone_id:
            raise ValueError(f"Zone not found for domain: {domain}")
        return zone_id

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

            logger.info(f"Setting A record for {domain} (zone: {zone_id}) -> {ip_address}")

            # Delete existing A records for this name
            self._delete_existing_records(zone_id, domain, "A")

            # Create new A record
            record_data = {
                "name": domain,
                "type": "A",
                "content": ip_address,
                "ttl": ttl,
            }

            result = self._make_request("POST", f"zones/{zone_id}/dns_records", record_data)
            if result.get("success", False):
                record_id = result.get("result", {}).get("id")
                logger.info(f"Created A record {record_id} for {domain}")
                return True
            else:
                logger.error(f"Failed to create A record for {domain}")
                return False

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

            logger.info(f"Setting CAA record for {domain} (zone: {zone_id})")

            # Delete existing CAA records for this name
            self._delete_existing_records(zone_id, domain, "CAA")

            # Create CAA record for Let's Encrypt
            record_data = {
                "name": domain,
                "type": "CAA",
                "data": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
                "ttl": ttl,
            }

            result = self._make_request("POST", f"zones/{zone_id}/dns_records", record_data)
            if result.get("success", False):
                record_id = result.get("result", {}).get("id")
                logger.info(f"Created CAA record {record_id} for {domain}")
                return True
            else:
                logger.error(f"Failed to create CAA record for {domain}")
                return False

        except Exception as e:
            logger.error(f"Failed to create CAA record for {domain}: {e}")
            return False

    def _delete_existing_records(
        self, zone_id: str, record_name: str, record_type: str
    ) -> None:
        """Delete existing records of specified type and name."""
        try:
            # List existing records
            params = f"zones/{zone_id}/dns_records?name={record_name}&type={record_type}"
            result = self._make_request("GET", params)

            if not result.get("success", False):
                logger.warning(f"Failed to list existing {record_type} records for {record_name}")
                return

            records = result.get("result", [])
            # Delete each record
            for record in records:
                record_id = record.get("id")
                if record_id:
                    logger.debug(
                        f"Deleting existing {record_type} record {record_id} for {record_name}"
                    )
                    delete_result = self._make_request(
                        "DELETE", f"zones/{zone_id}/dns_records/{record_id}"
                    )
                    if not delete_result.get("success", False):
                        logger.warning(f"Failed to delete record {record_id}")

        except Exception as e:
            logger.warning(
                f"Failed to delete existing {record_type} records for {record_name}: {e}"
            )

    def get_dns_records(
        self, domain: str, record_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
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

            params = f"zones/{zone_id}/dns_records?name={domain}"
            if record_type:
                params += f"&type={record_type}"

            result = self._make_request("GET", params)

            if not result.get("success", False):
                logger.error(f"Failed to get DNS records for {domain}")
                return []

            return result.get("result", [])

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

            # Delete A and CAA records
            self._delete_existing_records(zone_id, domain, "A")
            self._delete_existing_records(zone_id, domain, "CAA")

            logger.info(f"Cleaned up DNS records for {domain}")
            return True

        except Exception as e:
            logger.error(f"Failed to cleanup DNS records for {domain}: {e}")
            return False
