"""
Simple user authentication middleware for protecting user routes.
"""

import os
from typing import Optional
from fastapi import HTTPException, Header
from log import init_logger

logger = init_logger(__name__)


def get_user_token() -> Optional[str]:
    """Get the user token from environment configuration."""
    return os.getenv("USER_TOKEN")


def verify_user_token(
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Verify the user token from Authorization header.

    Args:
        authorization: The Authorization header value (expected format: "Bearer <token>")

    Raises:
        HTTPException: If authentication fails

    Returns:
        None if authentication succeeds
    """
    user_token = get_user_token()

    # If no user token is configured, allow access (for development/testing)
    if not user_token:
        logger.warning(
            "No USER_TOKEN configured - user routes are accessible without authentication"
        )
        return

    # Check if Authorization header is present
    if not authorization:
        logger.warning("User access denied: Missing Authorization header")
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Missing Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract token from "Bearer <token>" format
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning("User access denied: Invalid Authorization header format")
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Expected: 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]

    # Verify token matches
    if token != user_token:
        logger.warning("User access denied: Invalid token provided")
        raise HTTPException(
            status_code=403,
            detail="Invalid user token. Access denied.",
        )

    logger.debug("User authentication successful")


def require_user_token():
    """
    Dependency function that can be used in FastAPI route handlers.

    Usage:
        @router.post("/v1/chat/completions")
        async def chat_completions(request: Request, _auth: None = Depends(require_user_token())):
            # Your route logic here
            pass
    """

    def dependency(authorization: Optional[str] = Header(None, alias="Authorization")):
        verify_user_token(authorization)
        return None

    return dependency
