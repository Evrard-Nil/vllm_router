"""
Main domain registration service.
Coordinates certificate management, DNS operations, and TLS attestation.
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

from domain_registration.env_config import DomainRegistrationConfig
from domain_registration.cert_manager import CertificateManager
from domain_registration.attestation_service import AttestationService

logger = logging.getLogger(__name__)

# Global service instance
_domain_service: Optional["DomainRegistrationService"] = None


class DomainRegistrationService:
    """Main service for domain registration operations."""

    def __init__(self):
        """Initialize the domain registration service."""
        self.config = DomainRegistrationConfig.from_env()
        self.cert_manager: Optional[CertificateManager] = None
        self.attestation_service: Optional[AttestationService] = None
        self._renewal_task: Optional[asyncio.Task] = None
        self._initialized = False
        self._last_renewal_check: Optional[datetime] = None

    async def initialize(self) -> bool:
        """
        Initialize the domain registration service.

        Returns:
            True if initialization successful
        """
        if self._initialized:
            logger.debug("Domain registration service already initialized")
            return True

        try:
            if not self.config.enabled:
                logger.info("Domain registration is disabled")
                self._initialized = True
                return True

            logger.info("Initializing domain registration service")

            # Validate configuration
            errors = self.config.validate()
            if errors:
                logger.error(f"Configuration validation failed: {errors}")
                return False

            # Validate static IP matches machine IP
            if not self.config.validate_static_ip_matches_machine():
                logger.warning("Static IP validation failed, but continuing")

            # Initialize certificate manager
            self.cert_manager = CertificateManager(self.config)

            # Validate certificate manager setup
            cert_errors = self.cert_manager.validate_setup()
            if cert_errors:
                logger.error(
                    f"Certificate manager setup validation failed: {cert_errors}"
                )
                return False

            # Initialize attestation service
            self.attestation_service = AttestationService(self.config)

            # Process existing certificates
            success, needs_evidence = await self._process_certificates()
            if not success:
                logger.error("Initial certificate processing failed")
                return False

            # Generate evidence if needed
            if needs_evidence:
                evidence_success = self.attestation_service.generate_evidence_if_needed(
                    self.config.domains, force=True
                )
                if not evidence_success:
                    logger.warning("Initial evidence generation failed")

            # Start renewal monitoring
            if self.config.auto_renew:
                self._renewal_task = asyncio.create_task(self._renewal_monitor())
                logger.info("Started certificate renewal monitoring")

            self._initialized = True
            logger.info("Domain registration service initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize domain registration service: {e}")
            return False

    async def _process_certificates(self) -> tuple[bool, bool]:
        """
        Process all certificates (obtain or renew as needed).

        Returns:
            (success, needs_evidence) tuple
        """
        if not self.cert_manager:
            return False, False

        try:
            success, needs_evidence = self.cert_manager.process_all_domains()
            return success, needs_evidence
        except Exception as e:
            logger.error(f"Failed to process certificates: {e}")
            return False, False

    async def _renewal_monitor(self) -> None:
        """Background task to monitor and renew certificates."""
        logger.info("Starting certificate renewal monitor")

        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour

                if not self.config.auto_renew or not self.cert_manager:
                    continue

                # Check if any certificates need renewal
                needs_renewal = False
                for domain in self.config.domains:
                    if self.cert_manager.is_certificate_expiring_soon(domain):
                        needs_renewal = True
                        break

                if needs_renewal:
                    logger.info("Certificates need renewal, processing...")
                    success, needs_evidence = await self._process_certificates()

                    if success and needs_evidence and self.attestation_service:
                        # Generate new evidence after certificate changes
                        evidence_success = (
                            self.attestation_service.generate_evidence_if_needed(
                                self.config.domains, force=True
                            )
                        )
                        if evidence_success:
                            logger.info(
                                "Evidence regenerated after certificate renewal"
                            )
                        else:
                            logger.warning("Evidence regeneration failed after renewal")

                    self._last_renewal_check = datetime.utcnow()

            except asyncio.CancelledError:
                logger.info("Renewal monitor cancelled")
                break
            except Exception as e:
                logger.error(f"Error in renewal monitor: {e}")
                # Continue monitoring despite errors

    async def renew_certificates(self) -> Dict[str, Any]:
        """
        Manually renew all certificates.

        Returns:
            Renewal result dictionary
        """
        if not self._initialized or not self.cert_manager:
            return {
                "success": False,
                "error": "Domain registration service not initialized",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            logger.info("Manual certificate renewal requested")
            success, needs_evidence = await self._process_certificates()

            result = {
                "success": success,
                "needs_evidence": needs_evidence,
                "timestamp": datetime.utcnow().isoformat(),
                "domains_processed": len(self.config.domains)
                if self.config.domains
                else 0,
            }

            # Generate evidence if certificates changed
            if success and needs_evidence and self.attestation_service:
                evidence_success = self.attestation_service.generate_evidence_if_needed(
                    self.config.domains, force=True
                )
                result["evidence_generated"] = evidence_success

            return result

        except Exception as e:
            logger.error(f"Manual certificate renewal failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def get_status(self) -> Dict[str, Any]:
        """
        Get current status of domain registration service.

        Returns:
            Status dictionary
        """
        try:
            status = {
                "initialized": self._initialized,
                "enabled": self.config.enabled,
                "timestamp": datetime.utcnow().isoformat(),
                "config": {
                    "domains": self.config.domains,
                    "static_ip": self.config.static_ip,
                    "auto_renew": self.config.auto_renew,
                    "renewal_threshold_days": self.config.renewal_threshold_days,
                    "attestation_enabled": self.config.attestation_enabled,
                },
            }

            if not self.config.enabled:
                return status

            if not self._initialized:
                status["error"] = "Service not initialized"
                return status

            # Add certificate status
            if self.cert_manager:
                cert_status = {}
                for domain in self.config.domains:
                    cert_status[domain] = {
                        "exists": self.cert_manager.certificate_exists(domain),
                        "expiring_soon": self.cert_manager.is_certificate_expiring_soon(
                            domain
                        ),
                        "expiration": self.cert_manager.get_certificate_expiration(
                            domain
                        ).isoformat()
                        if self.cert_manager.get_certificate_expiration(domain)
                        else None,
                    }
                status["certificates"] = cert_status

            # Add attestation status
            if self.attestation_service:
                status["attestation"] = (
                    self.attestation_service.get_attestation_status()
                )

            # Add renewal monitor status
            status["renewal_monitor"] = {
                "active": self._renewal_task is not None
                and not self._renewal_task.done(),
                "last_check": self._last_renewal_check.isoformat()
                if self._last_renewal_check
                else None,
            }

            return status

        except Exception as e:
            logger.error(f"Failed to get domain registration status: {e}")
            return {
                "initialized": self._initialized,
                "enabled": self.config.enabled,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def get_evidence(self) -> Dict[str, Any]:
        """
        Get attestation evidence.

        Returns:
            Evidence dictionary
        """
        if not self._initialized or not self.attestation_service:
            return {
                "error": "Domain registration service not initialized or attestation disabled",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            return self.attestation_service.get_evidence_for_verification()
        except Exception as e:
            logger.error(f"Failed to get evidence: {e}")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}

    async def verify_attestation(self, include_details: bool = False) -> Dict[str, Any]:
        """
        Verify attestation evidence.

        Args:
            include_details: Include detailed verification information

        Returns:
            Verification result dictionary
        """
        if not self._initialized or not self.attestation_service:
            return {
                "valid": False,
                "error": "Domain registration service not initialized or attestation disabled",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            return self.attestation_service.verify_attestation(include_details)
        except Exception as e:
            logger.error(f"Failed to verify attestation: {e}")
            return {
                "valid": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def force_regenerate_evidence(self) -> Dict[str, Any]:
        """
        Force regeneration of attestation evidence.

        Returns:
            Result dictionary
        """
        if not self._initialized or not self.attestation_service:
            return {
                "success": False,
                "error": "Domain registration service not initialized or attestation disabled",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            success = self.attestation_service.force_regenerate_evidence(
                self.config.domains
            )
            return {"success": success, "timestamp": datetime.utcnow().isoformat()}
        except Exception as e:
            logger.error(f"Failed to force regenerate evidence: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def cleanup(self) -> None:
        """Cleanup resources and stop background tasks."""
        logger.info("Cleaning up domain registration service")

        if self._renewal_task and not self._renewal_task.done():
            self._renewal_task.cancel()
            try:
                await self._renewal_task
            except asyncio.CancelledError:
                pass

        self._initialized = False
        logger.info("Domain registration service cleanup completed")

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get metrics for monitoring.

        Returns:
            Metrics dictionary
        """
        try:
            metrics = {
                "initialized": self._initialized,
                "enabled": self.config.enabled,
                "timestamp": datetime.utcnow().isoformat(),
            }

            if self._initialized and self.config.enabled:
                # Add certificate metrics
                if self.cert_manager:
                    cert_metrics = {
                        "total_domains": len(self.config.domains),
                        "certificates_exist": 0,
                        "certificates_expiring": 0,
                    }

                    for domain in self.config.domains:
                        if self.cert_manager.certificate_exists(domain):
                            cert_metrics["certificates_exist"] += 1
                        if self.cert_manager.is_certificate_expiring_soon(domain):
                            cert_metrics["certificates_expiring"] += 1

                    metrics["certificates"] = cert_metrics

                # Add attestation metrics
                if self.attestation_service:
                    metrics["attestation"] = (
                        self.attestation_service.get_attestation_metrics()
                    )

                # Add renewal monitor metrics
                metrics["renewal_monitor"] = {
                    "active": self._renewal_task is not None
                    and not self._renewal_task.done(),
                    "last_check": self._last_renewal_check.isoformat()
                    if self._last_renewal_check
                    else None,
                }

            return metrics

        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return {
                "initialized": self._initialized,
                "enabled": self.config.enabled,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }


def get_domain_registration_service() -> Optional[DomainRegistrationService]:
    """
    Get the global domain registration service instance.

    Returns:
        Domain registration service instance or None
    """
    return _domain_service


def set_domain_registration_service(service: DomainRegistrationService) -> None:
    """
    Set the global domain registration service instance.

    Args:
        service: Domain registration service instance
    """
    global _domain_service
    _domain_service = service


async def initialize_domain_registration_service() -> bool:
    """
    Initialize the global domain registration service.

    Returns:
        True if initialization successful
    """
    global _domain_service

    if _domain_service is None:
        _domain_service = DomainRegistrationService()

    return await _domain_service.initialize()


async def cleanup_domain_registration_service() -> None:
    """Cleanup the global domain registration service."""
    global _domain_service

    if _domain_service:
        await _domain_service.cleanup()
        _domain_service = None
