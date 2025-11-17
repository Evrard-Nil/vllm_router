"""
Admin authentication middleware for protecting sensitive routes.
"""

import os
from typing import Optional
from fastapi import HTTPException, Header, Request
from log import init_logger

logger = init_logger(__name__)


def get_admin_token() -> Optional[str]:
    """Get the admin token from environment configuration."""
    return os.getenv("ADMIN_TOKEN")


def verify_admin_token(
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Verify the admin token from Authorization header.

    Args:
        authorization: The Authorization header value (expected format: "Bearer <token>")

    Raises:
        HTTPException: If authentication fails

    Returns:
        None if authentication succeeds
    """
    admin_token = get_admin_token()

    # If no admin token is configured, allow access (for development/testing)
    if not admin_token:
        logger.warning(
            "No ADMIN_TOKEN configured - admin routes are accessible without authentication"
        )
        return

    # Check if Authorization header is present
    if not authorization:
        logger.warning("Admin access denied: Missing Authorization header")
        raise HTTPException(
            status_code=401,
            detail="Admin access required. Missing Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract token from "Bearer <token>" format
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning("Admin access denied: Invalid Authorization header format")
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Expected: 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]

    # Verify token matches
    if token != admin_token:
        logger.warning("Admin access denied: Invalid token provided")
        raise HTTPException(
            status_code=403,
            detail="Invalid admin token. Access denied.",
        )

    logger.debug("Admin authentication successful")


async def admin_auth_middleware(request: Request, call_next):
    """
    FastAPI middleware for admin authentication.
    This middleware can be applied to protect entire router prefixes.
    """
    # Check if this is an admin route
    if request.url.path.startswith("/admin/"):
        await verify_admin_token_request(request)

    response = await call_next(request)
    return response


async def verify_admin_token_request(request: Request):
    """
    Verify admin token for a given request.

    Args:
        request: The FastAPI request object

    Raises:
        HTTPException: If authentication fails
    """
    admin_token = get_admin_token()

    # If no admin token is configured, allow access
    if not admin_token:
        logger.warning(
            "No ADMIN_TOKEN configured - admin routes are accessible without authentication"
        )
        return

    # Get Authorization header
    authorization = request.headers.get("Authorization")

    if not authorization:
        logger.warning(
            f"Admin access denied to {request.url.path}: Missing Authorization header"
        )
        raise HTTPException(
            status_code=401,
            detail="Admin access required. Missing Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract token from "Bearer <token>" format
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning(
            f"Admin access denied to {request.url.path}: Invalid Authorization header format"
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Expected: 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]

    # Verify token matches
    if token != admin_token:
        logger.warning(
            f"Admin access denied to {request.url.path}: Invalid token provided"
        )
        raise HTTPException(
            status_code=403,
            detail="Invalid admin token. Access denied.",
        )

    logger.debug(f"Admin authentication successful for {request.url.path}")


def require_admin_token():
    """
    Dependency function that can be used in FastAPI route handlers.

    Usage:
        @router.post("/admin/some-route")
        async def some_route(request: Request, _auth: None = Depends(require_admin_token())):
            # Your route logic here
            pass
    """

    def dependency(authorization: Optional[str] = Header(None, alias="Authorization")):
        verify_admin_token(authorization)
        return None

    return dependency
