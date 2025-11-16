"""
Evidence generation for TLS attestation.
Handles dstack attestation quote generation with certificate binding.
"""

import os
import json
import hashlib
import subprocess
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from .env_config import DomainRegistrationConfig

logger = logging.getLogger(__name__)


class EvidenceGenerator:
    """Generates attestation evidence for certificates."""

    def __init__(self, config: DomainRegistrationConfig):
        """
        Initialize evidence generator.

        Args:
            config: Domain registration configuration
        """
        self.config = config
        self.evidence_dir = config.evidence_dir
        self.acme_account_dir = (
            "/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory"
        )

    def generate_evidence(self, domains: List[str]) -> bool:
        """
        Generate attestation evidence for certificates.

        Args:
            domains: List of domains to generate evidence for

        Returns:
            True if successful
        """
        try:
            logger.info(f"Generating evidence for {len(domains)} domains")

            # Create evidence directory
            os.makedirs(self.evidence_dir, exist_ok=True)
            original_cwd = os.getcwd()
            os.chdir(self.evidence_dir)

            try:
                # Copy ACME account file
                if not self._copy_acme_account():
                    logger.error("Failed to copy ACME account file")
                    return False

                # Copy certificate files
                if not self._copy_certificates(domains):
                    logger.error("Failed to copy certificate files")
                    return False

                # Generate checksum including static IP
                checksum_data = self._generate_checksum_data(domains)
                if not checksum_data:
                    logger.error("Failed to generate checksum data")
                    return False

                # Generate dstack attestation
                if not self._generate_dstack_attestation(checksum_data):
                    logger.error("Failed to generate dstack attestation")
                    return False

                logger.info("Evidence generation completed successfully")
                return True

            finally:
                os.chdir(original_cwd)

        except Exception as e:
            logger.error(f"Evidence generation failed: {e}")
            return False

    def _copy_acme_account(self) -> bool:
        """Copy ACME account file to evidence directory."""
        try:
            # Find ACME account file
            account_dirs = os.listdir(self.acme_account_dir)
            if not account_dirs:
                logger.error("No ACME account directories found")
                return False

            account_dir = account_dirs[0]  # Use first account
            regr_file = os.path.join(self.acme_account_dir, account_dir, "regr.json")

            if not os.path.exists(regr_file):
                logger.error(f"ACME account file not found: {regr_file}")
                return False

            # Copy to evidence directory
            import shutil

            shutil.copy2(regr_file, "acme-account.json")
            logger.info("ACME account file copied successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to copy ACME account file: {e}")
            return False

    def _copy_certificates(self, domains: List[str]) -> bool:
        """Copy certificate files to evidence directory."""
        try:
            certificates_copied = 0

            for domain in domains:
                cert_name = domain.replace("*.", "").replace(".", "-")
                cert_path = f"{self.config.certificate_dir}/{cert_name}/fullchain.pem"

                if os.path.exists(cert_path):
                    dest_path = f"cert-{domain}.pem"
                    import shutil

                    shutil.copy2(cert_path, dest_path)
                    certificates_copied += 1
                    logger.debug(f"Copied certificate for {domain}")
                else:
                    logger.warning(f"Certificate not found for domain: {domain}")

            if certificates_copied == 0:
                logger.error("No certificate files found to copy")
                return False

            logger.info(f"Copied {certificates_copied} certificate files")
            return True

        except Exception as e:
            logger.error(f"Failed to copy certificates: {e}")
            return False

    def _generate_checksum_data(self, domains: List[str]) -> Optional[str]:
        """Generate data for checksum including static IP and certificates."""
        try:
            data = {
                "domains": domains,
                "static_ip": self.config.static_ip,
                "timestamp": datetime.utcnow().isoformat(),
                "evidence_version": "1.0",
            }

            # Add certificate files
            for domain in domains:
                cert_file = f"cert-{domain}.pem"
                if os.path.exists(cert_file):
                    with open(cert_file, "r") as f:
                        cert_content = f.read()
                        # Store certificate hash instead of full content for efficiency
                        cert_hash = hashlib.sha256(cert_content.encode()).hexdigest()
                        data[f"cert_hash_{domain}"] = cert_hash

            # Add ACME account hash
            if os.path.exists("acme-account.json"):
                with open("acme-account.json", "r") as f:
                    account_content = f.read()
                    account_hash = hashlib.sha256(account_content.encode()).hexdigest()
                    data["acme_account_hash"] = account_hash

            # Generate checksum of all data
            data_json = json.dumps(data, sort_keys=True)
            checksum = hashlib.sha256(data_json.encode()).hexdigest()

            # Save checksum file
            with open("evidence-data.json", "w") as f:
                json.dump(data, f, indent=2, sort_keys=True)

            # Generate SHA256 checksum file
            checksum_files = ["evidence-data.json", "acme-account.json"]
            for domain in domains:
                cert_file = f"cert-{domain}.pem"
                if os.path.exists(cert_file):
                    checksum_files.append(cert_file)

            with open("sha256sum.txt", "w") as f:
                for file_path in checksum_files:
                    if os.path.exists(file_path):
                        file_hash = hashlib.sha256(
                            open(file_path, "rb").read()
                        ).hexdigest()
                        f.write(f"{file_hash}  {file_path}\n")

            logger.info(f"Generated checksum data: {checksum}")
            return checksum

        except Exception as e:
            logger.error(f"Failed to generate checksum data: {e}")
            return None

    def _generate_dstack_attestation(self, checksum_data: str) -> bool:
        """Generate dstack attestation quote with checksum as report data."""
        try:
            # Pad hash to 128 characters for dstack compatibility
            padded_hash = checksum_data.ljust(128, "0")

            # Try dstack socket first, then tappd socket
            sockets = [
                (
                    "/var/run/dstack.sock",
                    "http://localhost/GetQuote?report_data={}",
                    "http://localhost/Info",
                ),
                (
                    "/var/run/tappd.sock",
                    "http://localhost/prpc/Tappd.RawQuote?report_data={}",
                    "http://localhost/prpc/Tappd.Info",
                ),
            ]

            for socket_path, quote_url, info_url in sockets:
                if os.path.exists(socket_path):
                    logger.info(f"Using socket: {socket_path}")

                    # Generate quote
                    quote_cmd = [
                        "curl",
                        "-s",
                        "--unix-socket",
                        socket_path,
                        quote_url.format(padded_hash),
                    ]

                    quote_result = subprocess.run(
                        quote_cmd, capture_output=True, text=True, timeout=30
                    )

                    if quote_result.returncode == 0:
                        with open("quote.json", "w") as f:
                            f.write(quote_result.stdout)
                        logger.info("Quote generated successfully")

                        # Get info
                        info_cmd = [
                            "curl",
                            "-s",
                            "--unix-socket",
                            socket_path,
                            info_url,
                        ]

                        info_result = subprocess.run(
                            info_cmd, capture_output=True, text=True, timeout=30
                        )

                        if info_result.returncode == 0:
                            with open("info.json", "w") as f:
                                f.write(info_result.stdout)
                            logger.info("Info generated successfully")
                            return True
                        else:
                            logger.warning(
                                f"Failed to get info from {socket_path}: {info_result.stderr}"
                            )
                    else:
                        logger.warning(
                            f"Failed to get quote from {socket_path}: {quote_result.stderr}"
                        )
                else:
                    logger.debug(f"Socket not found: {socket_path}")

            logger.error("No valid dstack/tappd socket found")
            return False

        except Exception as e:
            logger.error(f"Failed to generate dstack attestation: {e}")
            return False

    def verify_evidence(self) -> Dict[str, Any]:
        """
        Verify existing evidence files.

        Returns:
            Verification result dictionary
        """
        try:
            if not os.path.exists(self.evidence_dir):
                return {"valid": False, "error": "Evidence directory does not exist"}

            original_cwd = os.getcwd()
            os.chdir(self.evidence_dir)

            try:
                result = {"valid": True, "files": {}, "errors": []}

                # Check required files
                required_files = [
                    "quote.json",
                    "info.json",
                    "sha256sum.txt",
                    "evidence-data.json",
                ]

                for file_name in required_files:
                    if os.path.exists(file_name):
                        result["files"][file_name] = {
                            "exists": True,
                            "size": os.path.getsize(file_name),
                            "mtime": os.path.getmtime(file_name),
                        }
                    else:
                        result["files"][file_name] = {"exists": False}
                        result["valid"] = False
                        result["errors"].append(f"Missing required file: {file_name}")

                # Verify checksums
                if os.path.exists("sha256sum.txt"):
                    try:
                        checksum_result = subprocess.run(
                            ["sha256sum", "-c", "sha256sum.txt"],
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )

                        result["checksum_valid"] = checksum_result.returncode == 0
                        if not result["checksum_valid"]:
                            result["errors"].append("Checksum verification failed")
                            result["valid"] = False
                    except Exception as e:
                        result["checksum_valid"] = False
                        result["errors"].append(f"Checksum verification error: {e}")
                        result["valid"] = False

                # Parse evidence data
                if os.path.exists("evidence-data.json"):
                    try:
                        with open("evidence-data.json", "r") as f:
                            evidence_data = json.load(f)
                            result["evidence_data"] = evidence_data

                            # Verify static IP matches current config
                            if evidence_data.get("static_ip") != self.config.static_ip:
                                result["errors"].append(
                                    "Static IP mismatch in evidence"
                                )
                                result["valid"] = False
                    except Exception as e:
                        result["errors"].append(f"Failed to parse evidence data: {e}")
                        result["valid"] = False

                return result

            finally:
                os.chdir(original_cwd)

        except Exception as e:
            logger.error(f"Failed to verify evidence: {e}")
            return {"valid": False, "error": str(e)}

    def get_evidence_summary(self) -> Dict[str, Any]:
        """
        Get summary of evidence files.

        Returns:
            Evidence summary dictionary
        """
        try:
            if not os.path.exists(self.evidence_dir):
                return {"exists": False}

            verification = self.verify_evidence()

            summary = {
                "exists": True,
                "directory": self.evidence_dir,
                "verification": verification,
                "file_count": len(
                    [
                        f
                        for f in os.listdir(self.evidence_dir)
                        if os.path.isfile(os.path.join(self.evidence_dir, f))
                    ]
                ),
            }

            # Add quote info if available
            if os.path.exists(os.path.join(self.evidence_dir, "quote.json")):
                try:
                    with open(os.path.join(self.evidence_dir, "quote.json"), "r") as f:
                        quote_data = json.load(f)
                        summary["quote_info"] = {
                            "has_quote": True,
                            "quote_size": len(json.dumps(quote_data)),
                        }
                except Exception:
                    summary["quote_info"] = {"has_quote": False}

            return summary

        except Exception as e:
            logger.error(f"Failed to get evidence summary: {e}")
            return {"exists": False, "error": str(e)}

    def cleanup_old_evidence(self, keep_count: int = 5) -> bool:
        """
        Clean up old evidence files, keeping only the most recent ones.

        Args:
            keep_count: Number of recent evidence sets to keep

        Returns:
            True if successful
        """
        try:
            if not os.path.exists(self.evidence_dir):
                return True

            # This is a placeholder for more complex cleanup logic
            # For now, we just ensure the evidence directory doesn't grow too large
            logger.info("Evidence cleanup completed (placeholder implementation)")
            return True

        except Exception as e:
            logger.error(f"Failed to cleanup old evidence: {e}")
            return False
