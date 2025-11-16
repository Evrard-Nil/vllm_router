"""
Attestation service for domain registration.
Manages evidence generation and verification for TLS attestation.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from .env_config import DomainRegistrationConfig
from .evidence_generator import EvidenceGenerator

logger = logging.getLogger(__name__)


class AttestationService:
    """Service for managing TLS attestation evidence."""

    def __init__(self, config: DomainRegistrationConfig):
        """
        Initialize attestation service.

        Args:
            config: Domain registration configuration
        """
        self.config = config
        self.evidence_generator = EvidenceGenerator(config)
        self.last_evidence_time: Optional[datetime] = None
        self.evidence_cache: Dict[str, Any] = {}

    def generate_evidence_if_needed(
        self, domains: List[str], force: bool = False
    ) -> bool:
        """
        Generate evidence if needed or forced.

        Args:
            domains: List of domains to generate evidence for
            force: Force generation even if not needed

        Returns:
            True if evidence was generated or already valid
        """
        if not self.config.attestation_enabled:
            logger.info("Attestation is disabled, skipping evidence generation")
            return True

        try:
            # Check if evidence already exists and is valid
            if not force:
                existing_evidence = self.evidence_generator.verify_evidence()
                if existing_evidence.get("valid", False):
                    # Check if evidence is recent (within 24 hours)
                    evidence_age = self._get_evidence_age()
                    if evidence_age and evidence_age < timedelta(hours=24):
                        logger.info(
                            f"Existing evidence is valid and recent ({evidence_age} old)"
                        )
                        return True
                    else:
                        logger.info(
                            f"Existing evidence is old ({evidence_age}), regenerating"
                        )
                else:
                    logger.info("No valid evidence found, generating new evidence")

            # Generate new evidence
            success = self.evidence_generator.generate_evidence(domains)
            if success:
                self.last_evidence_time = datetime.utcnow()
                self._update_evidence_cache()
                logger.info("Evidence generation completed successfully")
            else:
                logger.error("Evidence generation failed")

            return success

        except Exception as e:
            logger.error(f"Failed to generate evidence: {e}")
            return False

    def _get_evidence_age(self) -> Optional[timedelta]:
        """Get the age of existing evidence."""
        try:
            evidence_dir = self.config.evidence_dir
            if not os.path.exists(evidence_dir):
                return None

            # Check the most recent file in evidence directory
            files = [
                os.path.join(evidence_dir, f)
                for f in os.listdir(evidence_dir)
                if os.path.isfile(os.path.join(evidence_dir, f))
            ]

            if not files:
                return None

            latest_file = max(files, key=os.path.getmtime)
            mtime = datetime.fromtimestamp(os.path.getmtime(latest_file))
            return datetime.utcnow() - mtime

        except Exception as e:
            logger.error(f"Failed to get evidence age: {e}")
            return None

    def _update_evidence_cache(self) -> None:
        """Update the evidence cache with current evidence data."""
        try:
            self.evidence_cache = self.evidence_generator.get_evidence_summary()
            self.evidence_cache["cached_at"] = datetime.utcnow().isoformat()
        except Exception as e:
            logger.error(f"Failed to update evidence cache: {e}")
            self.evidence_cache = {}

    def get_attestation_status(self) -> Dict[str, Any]:
        """
        Get current attestation status.

        Returns:
            Attestation status dictionary
        """
        try:
            status = {
                "enabled": self.config.attestation_enabled,
                "evidence_directory": self.config.evidence_dir,
                "last_generation": self.last_evidence_time.isoformat()
                if self.last_evidence_time
                else None,
                "evidence_age": str(self._get_evidence_age())
                if self._get_evidence_age()
                else None,
            }

            if self.config.attestation_enabled:
                # Get evidence summary
                evidence_summary = self.evidence_generator.get_evidence_summary()
                status["evidence"] = evidence_summary

                # Get verification status
                verification = self.evidence_generator.verify_evidence()
                status["verification"] = verification

                # Add cache info
                if self.evidence_cache:
                    status["cache"] = self.evidence_cache

            return status

        except Exception as e:
            logger.error(f"Failed to get attestation status: {e}")
            return {
                "enabled": self.config.attestation_enabled,
                "error": str(e),
                "evidence_directory": self.config.evidence_dir,
            }

    def verify_attestation(self, include_details: bool = False) -> Dict[str, Any]:
        """
        Verify attestation evidence.

        Args:
            include_details: Include detailed verification information

        Returns:
            Verification result dictionary
        """
        try:
            if not self.config.attestation_enabled:
                return {
                    "valid": False,
                    "error": "Attestation is disabled",
                    "enabled": False,
                }

            verification = self.evidence_generator.verify_evidence()

            result = {
                "valid": verification.get("valid", False),
                "enabled": True,
                "timestamp": datetime.utcnow().isoformat(),
                "evidence_directory": self.config.evidence_dir,
            }

            if include_details:
                result["details"] = verification
                result["evidence_summary"] = (
                    self.evidence_generator.get_evidence_summary()
                )

            # Add specific checks
            if verification.get("valid", False):
                result["checks"] = {
                    "files_exist": all(
                        file_info.get("exists", False)
                        for file_info in verification.get("files", {}).values()
                    ),
                    "checksums_valid": verification.get("checksum_valid", False),
                    "static_ip_matches": True,  # Already checked in verify_evidence
                }
            else:
                result["errors"] = verification.get("errors", [])

            return result

        except Exception as e:
            logger.error(f"Failed to verify attestation: {e}")
            return {
                "valid": False,
                "enabled": self.config.attestation_enabled,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def get_evidence_for_verification(self) -> Dict[str, Any]:
        """
        Get evidence data for external verification.

        Returns:
            Evidence data for verification
        """
        try:
            if not self.config.attestation_enabled:
                return {"error": "Attestation is disabled"}

            evidence_dir = self.config.evidence_dir
            if not os.path.exists(evidence_dir):
                return {"error": "Evidence directory does not exist"}

            # Read key evidence files
            evidence_data = {}

            try:
                # Read quote
                quote_file = os.path.join(evidence_dir, "quote.json")
                if os.path.exists(quote_file):
                    with open(quote_file, "r") as f:
                        evidence_data["quote"] = json.load(f)

                # Read info
                info_file = os.path.join(evidence_dir, "info.json")
                if os.path.exists(info_file):
                    with open(info_file, "r") as f:
                        evidence_data["info"] = json.load(f)

                # Read evidence data
                evidence_data_file = os.path.join(evidence_dir, "evidence-data.json")
                if os.path.exists(evidence_data_file):
                    with open(evidence_data_file, "r") as f:
                        evidence_data["evidence_data"] = json.load(f)

                # Add metadata
                evidence_data["metadata"] = {
                    "generated_at": self.last_evidence_time.isoformat()
                    if self.last_evidence_time
                    else None,
                    "static_ip": self.config.static_ip,
                    "domains": self.config.domains,
                    "evidence_version": "1.0",
                }

                return evidence_data

            except Exception as e:
                logger.error(f"Failed to read evidence files: {e}")
                return {"error": f"Failed to read evidence files: {e}"}

        except Exception as e:
            logger.error(f"Failed to get evidence for verification: {e}")
            return {"error": str(e)}

    def cleanup_old_evidence(self, max_age_days: int = 7) -> bool:
        """
        Clean up old evidence files.

        Args:
            max_age_days: Maximum age of evidence files to keep

        Returns:
            True if successful
        """
        try:
            if not self.config.attestation_enabled:
                logger.info("Attestation is disabled, skipping cleanup")
                return True

            evidence_dir = self.config.evidence_dir
            if not os.path.exists(evidence_dir):
                return True

            cutoff_time = datetime.utcnow() - timedelta(days=max_age_days)
            cleaned_files = []

            for filename in os.listdir(evidence_dir):
                file_path = os.path.join(evidence_dir, filename)
                if os.path.isfile(file_path):
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if file_time < cutoff_time:
                        try:
                            os.remove(file_path)
                            cleaned_files.append(filename)
                        except Exception as e:
                            logger.warning(
                                f"Failed to remove old evidence file {filename}: {e}"
                            )

            if cleaned_files:
                logger.info(
                    f"Cleaned up {len(cleaned_files)} old evidence files: {cleaned_files}"
                )
            else:
                logger.info("No old evidence files to clean up")

            # Update cache after cleanup
            self._update_evidence_cache()

            return True

        except Exception as e:
            logger.error(f"Failed to cleanup old evidence: {e}")
            return False

    def force_regenerate_evidence(self, domains: List[str]) -> bool:
        """
        Force regeneration of evidence.

        Args:
            domains: List of domains to generate evidence for

        Returns:
            True if successful
        """
        logger.info("Force regenerating evidence")
        return self.generate_evidence_if_needed(domains, force=True)

    def get_attestation_metrics(self) -> Dict[str, Any]:
        """
        Get metrics for monitoring attestation service.

        Returns:
            Metrics dictionary
        """
        try:
            metrics = {
                "enabled": self.config.attestation_enabled,
                "evidence_exists": os.path.exists(self.config.evidence_dir),
                "last_generation_time": self.last_evidence_time.isoformat()
                if self.last_evidence_time
                else None,
                "evidence_age_hours": None,
                "cache_valid": bool(self.evidence_cache),
            }

            if self.last_evidence_time:
                age = datetime.utcnow() - self.last_evidence_time
                metrics["evidence_age_hours"] = age.total_seconds() / 3600

            if self.config.attestation_enabled:
                evidence_age = self._get_evidence_age()
                if evidence_age:
                    metrics["evidence_file_age_hours"] = (
                        evidence_age.total_seconds() / 3600
                    )

                verification = self.evidence_generator.verify_evidence()
                metrics["evidence_valid"] = verification.get("valid", False)
                metrics["evidence_files_count"] = len(verification.get("files", {}))

                # Count valid files
                valid_files = sum(
                    1
                    for file_info in verification.get("files", {}).values()
                    if file_info.get("exists", False)
                )
                metrics["evidence_valid_files_count"] = valid_files

            return metrics

        except Exception as e:
            logger.error(f"Failed to get attestation metrics: {e}")
            return {"error": str(e), "enabled": self.config.attestation_enabled}
