"""
Certificate management for domain registration.
Handles Let's Encrypt certificate operations with Cloudflare DNS-01 challenges.
"""

import os
import sys
import subprocess
import logging
from typing import List, Tuple, Optional
from datetime import datetime, timedelta
from .env_config import DomainRegistrationConfig
from .cloudflare_dns import CloudflareDNSProvider

logger = logging.getLogger(__name__)


class CertificateManager:
    """Manages Let's Encrypt certificates using Cloudflare DNS-01 challenges."""

    def __init__(self, config: DomainRegistrationConfig):
        """
        Initialize certificate manager.

        Args:
            config: Domain registration configuration
        """
        self.config = config
        self.dns_provider = CloudflareDNSProvider(
            config.cloudflare_api_token, config.cloudflare_zone_id
        )
        self.credentials_path = "/etc/letsencrypt/cloudflare.ini"

    def setup_certbot_credentials(self) -> bool:
        """
        Setup Cloudflare credentials for certbot.

        Returns:
            True if successful
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.credentials_path), exist_ok=True)

            # Write credentials file
            credentials_content = (
                f"dns_cloudflare_api_token = {self.config.cloudflare_api_token}"
            )

            with open(self.credentials_path, "w") as f:
                f.write(credentials_content)

            # Set secure permissions
            os.chmod(self.credentials_path, 0o600)

            logger.info("Cloudflare credentials setup successful")
            return True

        except Exception as e:
            logger.error(f"Failed to setup Cloudflare credentials: {e}")
            return False

    def ensure_certbot_installed(self) -> bool:
        """
        Ensure certbot and cloudflare plugin are installed.

        Returns:
            True if successful
        """
        try:
            # Check if certbot is available
            result = subprocess.run(
                [sys.executable, "-m", "certbot", "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                logger.info(f"Certbot already installed: {result.stdout.strip()}")
            else:
                logger.info("Installing certbot...")
                install_result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "certbot"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if install_result.returncode != 0:
                    logger.error(f"Failed to install certbot: {install_result.stderr}")
                    return False

                logger.info("Certbot installed successfully")

            # Check if cloudflare plugin is available
            plugin_result = subprocess.run(
                [sys.executable, "-m", "certbot", "plugins"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if "dns-cloudflare" in plugin_result.stdout:
                logger.info("Cloudflare DNS plugin already available")
            else:
                logger.info("Installing certbot-dns-cloudflare...")
                plugin_install_result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "certbot-dns-cloudflare"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if plugin_install_result.returncode != 0:
                    logger.error(
                        f"Failed to install certbot-dns-cloudflare: {plugin_install_result.stderr}"
                    )
                    return False

                logger.info("Cloudflare DNS plugin installed successfully")

            return True

        except Exception as e:
            logger.error(f"Failed to ensure certbot installation: {e}")
            return False

    def obtain_certificate(self, domain: str) -> bool:
        """
        Obtain certificate for domain using DNS-01 challenge.

        Args:
            domain: Domain name

        Returns:
            True if successful
        """
        logger.info(f"Obtaining certificate for domain: {domain}")

        # Setup DNS records first
        if not self.dns_provider.set_a_record(domain, self.config.static_ip):
            logger.error(f"Failed to set A record for {domain}")
            return False

        if not self.dns_provider.set_caa_record(domain):
            logger.warning(f"Failed to set CAA record for {domain}")

        # Setup certbot credentials
        if not self.setup_certbot_credentials():
            logger.error("Failed to setup certbot credentials")
            return False

        # Ensure certbot is installed
        if not self.ensure_certbot_installed():
            logger.error("Failed to ensure certbot installation")
            return False

        # Build certbot command
        cmd = [
            sys.executable,
            "-m",
            "certbot",
            "certonly",
            "--dns-cloudflare",
            f"--dns-cloudflare-credentials={self.credentials_path}",
            "--non-interactive",
            "--agree-tos",
            "--email",
            self.config.email,
            "-d",
            domain,
            "--dns-cloudflare-propagation-seconds",
            "120",
            "--preferred-challenges",
            "dns-01",
            "--cert-name",
            domain.replace("*.", "").replace(".", "-"),  # Handle wildcards
        ]

        try:
            logger.info(f"Running certbot command: {' '.join(cmd[:8])}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                logger.info(f"Certificate obtained successfully for {domain}")
                return True
            else:
                logger.error(f"Certificate obtaining failed for {domain}")
                logger.error(f"stdout: {result.stdout}")
                logger.error(f"stderr: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Certificate obtaining timed out for {domain}")
            return False
        except Exception as e:
            logger.error(
                f"Certificate obtaining failed with exception for {domain}: {e}"
            )
            return False

    def renew_certificate(self, domain: str) -> Tuple[bool, bool]:
        """
        Renew certificate for domain.

        Args:
            domain: Domain name

        Returns:
            (success, renewed) - success status and whether renewal was actually performed
        """
        logger.info(f"Renewing certificate for domain: {domain}")

        # Ensure certbot is installed
        if not self.ensure_certbot_installed():
            logger.error("Failed to ensure certbot installation")
            return False, False

        # Build certbot renew command
        cmd = [
            sys.executable,
            "-m",
            "certbot",
            "renew",
            "--dns-cloudflare",
            f"--dns-cloudflare-credentials={self.credentials_path}",
            "--non-interactive",
            "--dns-cloudflare-propagation-seconds",
            "120",
            "--cert-name",
            domain.replace("*.", "").replace(".", "-"),
        ]

        try:
            logger.info("Running certbot renew command...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                # Check if renewal was actually performed
                if "No renewals were attempted" in result.stdout:
                    logger.info(f"No renewal needed for {domain}")
                    return True, False
                elif (
                    "renewed" in result.stdout.lower()
                    or "certificate renewed" in result.stdout.lower()
                ):
                    logger.info(f"Certificate renewed successfully for {domain}")
                    return True, True
                else:
                    logger.info(f"Certificate renewal completed for {domain}")
                    return True, True
            else:
                logger.error(f"Certificate renewal failed for {domain}")
                logger.error(f"stdout: {result.stdout}")
                logger.error(f"stderr: {result.stderr}")
                return False, False

        except subprocess.TimeoutExpired:
            logger.error(f"Certificate renewal timed out for {domain}")
            return False, False
        except Exception as e:
            logger.error(f"Certificate renewal failed with exception for {domain}: {e}")
            return False, False

    def certificate_exists(self, domain: str) -> bool:
        """
        Check if certificate exists for domain.

        Args:
            domain: Domain name

        Returns:
            True if certificate exists
        """
        cert_name = domain.replace("*.", "").replace(".", "-")
        cert_path = f"{self.config.certificate_dir}/{cert_name}/fullchain.pem"

        exists = os.path.isfile(cert_path)
        logger.debug(f"Certificate check for {domain} at {cert_path}: {exists}")
        return exists

    def get_certificate_expiration(self, domain: str) -> Optional[datetime]:
        """
        Get certificate expiration date.

        Args:
            domain: Domain name

        Returns:
            Expiration datetime or None if certificate doesn't exist
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert_name = domain.replace("*.", "").replace(".", "-")
            cert_path = f"{self.config.certificate_dir}/{cert_name}/fullchain.pem"

            if not os.path.isfile(cert_path):
                return None

            with open(cert_path, "rb") as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                return cert.not_valid_after

        except Exception as e:
            logger.error(f"Failed to get certificate expiration for {domain}: {e}")
            return None

    def is_certificate_expiring_soon(
        self, domain: str, days_threshold: Optional[int] = None
    ) -> bool:
        """
        Check if certificate is expiring soon.

        Args:
            domain: Domain name
            days_threshold: Days threshold (uses config default if not provided)

        Returns:
            True if certificate is expiring soon
        """
        if days_threshold is None:
            days_threshold = self.config.renewal_threshold_days

        expiration = self.get_certificate_expiration(domain)
        if expiration is None:
            return True  # No certificate means it needs to be obtained

        threshold_date = datetime.utcnow() + timedelta(days=days_threshold)
        is_expiring = expiration < threshold_date

        if is_expiring:
            days_left = (expiration - datetime.utcnow()).days
            logger.warning(f"Certificate for {domain} expires in {days_left} days")

        return is_expiring

    def process_domain(self, domain: str) -> Tuple[bool, bool]:
        """
        Process a single domain - obtain or renew certificate as needed.

        Args:
            domain: Domain name

        Returns:
            (success, needs_evidence) - success status and whether evidence should be generated
        """
        try:
            if self.certificate_exists(domain):
                if self.is_certificate_expiring_soon(domain):
                    logger.info(f"Renewing expiring certificate for {domain}")
                    success, renewed = self.renew_certificate(domain)
                    return success, renewed
                else:
                    logger.info(f"Certificate for {domain} is valid")
                    return True, False
            else:
                logger.info(f"Obtaining new certificate for {domain}")
                success = self.obtain_certificate(domain)
                return success, success  # Always generate evidence for new certificates

        except Exception as e:
            logger.error(f"Failed to process domain {domain}: {e}")
            return False, False

    def process_all_domains(self) -> Tuple[bool, bool]:
        """
        Process all configured domains.

        Returns:
            (success, needs_evidence) - overall success and whether evidence should be generated
        """
        if not self.config.domains:
            logger.warning("No domains configured")
            return True, False

        logger.info(f"Processing {len(self.config.domains)} domains")

        overall_success = True
        needs_evidence = False

        for domain in self.config.domains:
            success, domain_needs_evidence = self.process_domain(domain)
            overall_success = overall_success and success
            needs_evidence = needs_evidence or domain_needs_evidence

        if overall_success:
            logger.info("All domains processed successfully")
        else:
            logger.error("Some domains failed to process")

        return overall_success, needs_evidence

    def validate_setup(self) -> List[str]:
        """
        Validate the certificate manager setup.

        Returns:
            List of validation errors
        """
        errors = []

        # Validate DNS provider credentials
        if not self.dns_provider.validate_credentials():
            errors.append("Cloudflare API token validation failed")

        # Test DNS record creation (optional, can be expensive)
        # This could be added as an optional validation step

        return errors
