"""
API endpoints for domain registration.
Provides REST API for certificate management and TLS attestation.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field

from services.domain_registration_service import get_domain_registration_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/domain-registration", tags=["domain-registration"])


# Response models
class StatusResponse(BaseModel):
    """Response model for status endpoint."""

    initialized: bool
    enabled: bool
    timestamp: str
    config: Optional[Dict[str, Any]] = None
    certificates: Optional[Dict[str, Any]] = None
    attestation: Optional[Dict[str, Any]] = None
    renewal_monitor: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class RenewalResponse(BaseModel):
    """Response model for certificate renewal."""

    success: bool
    needs_evidence: bool
    timestamp: str
    domains_processed: int
    evidence_generated: Optional[bool] = None
    error: Optional[str] = None


class EvidenceResponse(BaseModel):
    """Response model for evidence endpoint."""

    quote: Optional[Dict[str, Any]] = None
    info: Optional[Dict[str, Any]] = None
    evidence_data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: str


class VerificationResponse(BaseModel):
    """Response model for attestation verification."""

    valid: bool
    enabled: bool
    timestamp: str
    evidence_directory: str
    checks: Optional[Dict[str, bool]] = None
    errors: Optional[list[str]] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class ForceRegenerateResponse(BaseModel):
    """Response model for force evidence regeneration."""

    success: bool
    timestamp: str
    error: Optional[str] = None


class MetricsResponse(BaseModel):
    """Response model for metrics endpoint."""

    initialized: bool
    enabled: bool
    timestamp: str
    certificates: Optional[Dict[str, Any]] = None
    attestation: Optional[Dict[str, Any]] = None
    renewal_monitor: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def get_service_or_404():
    """Get domain registration service or raise 404."""
    service = get_domain_registration_service()
    if not service:
        raise HTTPException(
            status_code=503, detail="Domain registration service not available"
        )
    return service


@router.get("/status", response_model=StatusResponse)
async def get_status():
    """
    Get domain registration status.

    Returns comprehensive status including configuration, certificates,
    attestation, and renewal monitor information.
    """
    try:
        service = get_service_or_404()
        status_data = await service.get_status()
        return StatusResponse(**status_data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get domain registration status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/renew", response_model=RenewalResponse)
async def renew_certificates(background_tasks: BackgroundTasks):
    """
    Manually renew all certificates.

    Forces renewal of all configured domains and generates new evidence
    if certificates were updated.
    """
    try:
        service = get_service_or_404()
        result = await service.renew_certificates()
        return RenewalResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to renew certificates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/evidence", response_model=EvidenceResponse)
async def get_evidence():
    """
    Get attestation evidence for verification.

    Returns the complete evidence package including dstack quote,
    info, and metadata for external verification.
    """
    try:
        service = get_service_or_404()
        evidence_data = await service.get_evidence()

        if "error" in evidence_data:
            raise HTTPException(status_code=404, detail=evidence_data["error"])

        return EvidenceResponse(**evidence_data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attestation/verify", response_model=VerificationResponse)
async def verify_attestation(
    include_details: bool = Query(
        default=False, description="Include detailed verification information"
    ),
):
    """
    Verify attestation evidence.

    Validates the integrity and authenticity of attestation evidence.
    """
    try:
        service = get_service_or_404()
        verification_data = await service.verify_attestation(include_details)
        return VerificationResponse(**verification_data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to verify attestation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attestation/regenerate", response_model=ForceRegenerateResponse)
async def force_regenerate_evidence(background_tasks: BackgroundTasks):
    """
    Force regeneration of attestation evidence.

    Creates new evidence regardless of existing evidence age.
    """
    try:
        service = get_service_or_404()
        result = await service.force_regenerate_evidence()
        return ForceRegenerateResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to force regenerate evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics():
    """
    Get metrics for monitoring domain registration service.

    Returns operational metrics including certificate status,
    attestation health, and renewal monitor state.
    """
    try:
        service = get_service_or_404()
        metrics_data = service.get_metrics()
        return MetricsResponse(**metrics_data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """
    Simple health check endpoint.

    Returns basic health status for load balancers and monitoring.
    """
    try:
        service = get_domain_registration_service()

        if not service:
            return {
                "status": "unavailable",
                "message": "Domain registration service not initialized",
            }

        # Get basic status without full details
        if hasattr(service, "_initialized") and service._initialized:
            return {
                "status": "healthy",
                "message": "Domain registration service is operational",
            }
        else:
            return {
                "status": "initializing",
                "message": "Domain registration service is initializing",
            }

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "message": str(e)}


@router.get("/config")
async def get_configuration():
    """
    Get current configuration (non-sensitive data only).

    Returns configuration without exposing secrets like API tokens.
    """
    try:
        service = get_service_or_404()

        # Return only non-sensitive configuration
        config = {
            "enabled": service.config.enabled,
            "domains": service.config.domains,
            "static_ip": service.config.static_ip,
            "auto_renew": service.config.auto_renew,
            "renewal_threshold_days": service.config.renewal_threshold_days,
            "attestation_enabled": service.config.attestation_enabled,
            "evidence_dir": service.config.evidence_dir,
            "certificate_dir": service.config.certificate_dir,
        }

        return {
            "config": config,
            "timestamp": service.config.get_domain_list_string()
            if service.config.domains
            else None,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates")
async def get_certificate_status():
    """
    Get detailed certificate status for all domains.

    Returns expiration dates, existence status, and renewal information.
    """
    try:
        service = get_service_or_404()

        if not service.cert_manager:
            raise HTTPException(
                status_code=503, detail="Certificate manager not available"
            )

        cert_status = {}
        for domain in service.config.domains:
            expiration = service.cert_manager.get_certificate_expiration(domain)
            cert_status[domain] = {
                "exists": service.cert_manager.certificate_exists(domain),
                "expiring_soon": service.cert_manager.is_certificate_expiring_soon(
                    domain
                ),
                "expiration": expiration.isoformat() if expiration else None,
                "days_until_expiry": (
                    (expiration.replace(tzinfo=None) - datetime.now()).days
                    if expiration
                    else None
                ),
            }

        # Get timestamp from first domain if available
        timestamp = None
        if service.config.domains:
            first_expiration = service.cert_manager.get_certificate_expiration(
                service.config.domains[0]
            )
            timestamp = first_expiration.isoformat() if first_expiration else None

        return {
            "certificates": cert_status,
            "total_domains": len(service.config.domains),
            "timestamp": timestamp,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get certificate status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cleanup")
async def cleanup_old_evidence(
    max_age_days: int = Query(
        default=7,
        ge=1,
        le=365,
        description="Maximum age of evidence files to keep (days)",
    ),
):
    """
    Clean up old evidence files.

    Removes evidence files older than the specified age.
    """
    try:
        service = get_service_or_404()

        if not service.attestation_service:
            raise HTTPException(
                status_code=503, detail="Attestation service not available"
            )

        success = service.attestation_service.cleanup_old_evidence(max_age_days)

        return {
            "success": success,
            "max_age_days": max_age_days,
            "message": "Cleanup completed successfully"
            if success
            else "Cleanup failed",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cleanup old evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))
