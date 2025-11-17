# Copyright 2024-2025 The vLLM Production Stack Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Request, Header, Depends
from pydantic import BaseModel
from log import init_logger

from service_discovery import get_service_discovery, ServiceDiscoveryType
from middleware.admin_auth import verify_admin_token

logger = init_logger(__name__)

backend_management_router = APIRouter()


class BackendRequest(BaseModel):
    url: str


class BackendResponse(BaseModel):
    success: bool
    message: str
    backend_url: str


class BackendsListResponse(BaseModel):
    backends: list[str]
    count: int


@backend_management_router.post("/backend", response_model=BackendResponse)
async def add_backend(
    request: Request,
    backend_request: BackendRequest,
    authorization: str = Header(None, alias="Authorization"),
):
    """
    Add a new backend to the router.

    Args:
        request: The FastAPI request object
        backend_request: Request containing the backend URL to add
        authorization: Authorization header with admin token

    Returns:
        BackendResponse: Response indicating success or failure

    Raises:
        HTTPException: If the backend cannot be added or authentication fails
    """
    # Verify admin token
    verify_admin_token(authorization)

    try:
        service_discovery = get_service_discovery()

        # Check if this is a BackendListServiceDiscovery instance
        if not hasattr(service_discovery, "add_backend"):
            raise HTTPException(
                status_code=501,
                detail="Backend management is only supported with BACKEND_LIST service discovery type",
            )

        # Attempt to add the backend
        success = service_discovery.add_backend(backend_request.url)

        if success:
            logger.info(f"Successfully added backend: {backend_request.url}")
            return BackendResponse(
                success=True,
                message=f"Backend {backend_request.url} added successfully",
                backend_url=backend_request.url,
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to add backend {backend_request.url}. Backend may already exist or be unreachable.",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding backend {backend_request.url}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while adding backend: {str(e)}",
        )


@backend_management_router.delete("/backend", response_model=BackendResponse)
async def remove_backend(
    request: Request,
    backend_request: BackendRequest,
    authorization: str = Header(None, alias="Authorization"),
):
    """
    Remove a backend from the router.

    Args:
        request: The FastAPI request object
        backend_request: Request containing the backend URL to remove
        authorization: Authorization header with admin token

    Returns:
        BackendResponse: Response indicating success or failure

    Raises:
        HTTPException: If the backend cannot be removed or authentication fails
    """
    # Verify admin token
    verify_admin_token(authorization)

    try:
        service_discovery = get_service_discovery()

        # Check if this is a BackendListServiceDiscovery instance
        if not hasattr(service_discovery, "remove_backend"):
            raise HTTPException(
                status_code=501,
                detail="Backend management is only supported with BACKEND_LIST service discovery type",
            )

        # Attempt to remove the backend
        success = service_discovery.remove_backend(backend_request.url)

        if success:
            logger.info(f"Successfully removed backend: {backend_request.url}")
            return BackendResponse(
                success=True,
                message=f"Backend {backend_request.url} removed successfully",
                backend_url=backend_request.url,
            )
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Backend {backend_request.url} not found or could not be removed",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing backend {backend_request.url}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while removing backend: {str(e)}",
        )


@backend_management_router.get("/backends", response_model=BackendsListResponse)
async def list_backends(
    request: Request, authorization: str = Header(None, alias="Authorization")
):
    """
    Get the current list of backends.

    Args:
        request: The FastAPI request object
        authorization: Authorization header with admin token

    Returns:
        BackendsListResponse: Response containing the list of backend URLs

    Raises:
        HTTPException: If the backends cannot be listed or authentication fails
    """
    # Verify admin token
    verify_admin_token(authorization)

    try:
        service_discovery = get_service_discovery()

        # Check if this is a BackendListServiceDiscovery instance
        if not hasattr(service_discovery, "get_backends"):
            raise HTTPException(
                status_code=501,
                detail="Backend listing is only supported with BACKEND_LIST service discovery type",
            )

        # Get the list of backends
        backends = service_discovery.get_backends()

        logger.info(f"Retrieved list of {len(backends)} backends")
        return BackendsListResponse(backends=backends, count=len(backends))

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing backends: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while listing backends: {str(e)}",
        )
