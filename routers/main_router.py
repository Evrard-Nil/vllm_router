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
import json
from hashlib import sha256
from typing import Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Request,
    HTTPException,
    Query,
    Header,
    Depends,
)
from fastapi.responses import JSONResponse, Response, StreamingResponse
from quote.quote import (
    ECDSA,
    ED25519,
    ecdsa_context,
    ed25519_context,
    generate_attestation,
    sign_chat,
)
from cache.cache import set_chat, get_chat
from middleware.user_auth import require_user_token

from log import init_logger
from protocols import ModelCard, ModelList
from service_discovery import get_service_discovery
from services.request_service.request import (
    route_general_request,
    route_general_transcriptions,
    route_sleep_wakeup_request,
)
from stats.engine_stats import get_engine_stats_scraper
from version import __version__

try:
    # Semantic cache integration
    from experimental.semantic_cache_integration import (
        check_semantic_cache,
    )

    semantic_cache_available = True
except ImportError:
    semantic_cache_available = False

main_router = APIRouter()

logger = init_logger(__name__)


async def route_general_request_with_signing(
    request: Request,
    endpoint: str,
    background_tasks: BackgroundTasks,
    x_request_hash: Optional[str] = None,
):
    """
    Route the incoming request to the backend server with signing functionality.

    This function extends the basic request routing to include:
    - Request hash calculation
    - Response signing and caching
    - Support for both streaming and non-streaming responses
    """
    # Calculate request hash
    request_body = await request.body()
    if x_request_hash:
        request_sha256 = x_request_hash
        logger.info(f"Using client-provided request hash: {request_sha256}")
    else:
        request_sha256 = sha256(request_body).hexdigest()
        logger.debug(f"Calculated request hash: {request_sha256}")

    # Check if this is a streaming request
    try:
        request_json = json.loads(request_body)
        is_streaming = request_json.get("stream", False)
    except json.JSONDecodeError:
        is_streaming = False

    if is_streaming:
        return await route_streaming_request_with_signing(
            request, endpoint, background_tasks, request_sha256, request_body
        )
    else:
        return await route_non_streaming_request_with_signing(
            request, endpoint, background_tasks, request_sha256, request_body
        )


async def route_streaming_request_with_signing(
    request: Request,
    endpoint: str,
    background_tasks: BackgroundTasks,
    request_sha256: str,
    request_body: bytes,
):
    """Handle streaming requests with signing."""
    # For now, use the original routing without signing for streaming
    # TODO: Implement proper streaming response signing
    logger.warning(
        "Streaming response signing not yet implemented, using original routing"
    )
    return await route_general_request(request, endpoint, background_tasks)


async def route_non_streaming_request_with_signing(
    request: Request,
    endpoint: str,
    background_tasks: BackgroundTasks,
    request_sha256: str,
    request_body: bytes,
):
    """Handle non-streaming requests with signing."""
    # Get the original response
    original_response = await route_general_request(request, endpoint, background_tasks)

    # Extract chat_id and sign the response
    if hasattr(original_response, "body") and original_response.body:
        try:
            # Convert body to string if it's bytes
            body_str = original_response.body
            if isinstance(body_str, bytes):
                body_str = body_str.decode("utf-8")

            response_data = json.loads(body_str)
            chat_id = response_data.get("id")

            if chat_id:
                response_sha256 = sha256(body_str.encode()).hexdigest()
                signed_data = sign_chat(f"{request_sha256}:{response_sha256}")
                set_chat(chat_id, json.dumps(signed_data))
                logger.info(f"Cached signature for non-streaming chat_id: {chat_id}")
        except (json.JSONDecodeError, AttributeError, UnicodeDecodeError):
            logger.warning("Failed to parse response for signing")

    return original_response


@main_router.post("/v1/chat/completions")
async def route_chat_completion(
    request: Request,
    background_tasks: BackgroundTasks,
    x_request_hash: Optional[str] = Header(None, alias="X-Request-Hash"),
    auth: str = Depends(require_user_token),
):
    if semantic_cache_available:
        # Check if the request can be served from the semantic cache
        logger.debug("Received chat completion request, checking semantic cache")
        cache_response = await check_semantic_cache(request=request)

        if cache_response:
            logger.info("Serving response from semantic cache")
            return cache_response

    logger.debug("No cache hit, forwarding request to backend")
    return await route_general_request_with_signing(
        request, "/v1/chat/completions", background_tasks, x_request_hash
    )


@main_router.post("/v1/completions")
async def route_completion(
    request: Request,
    background_tasks: BackgroundTasks,
    x_request_hash: Optional[str] = Header(None, alias="X-Request-Hash"),
    auth: str = Depends(require_user_token),
):
    return await route_general_request_with_signing(
        request, "/v1/completions", background_tasks, x_request_hash
    )


@main_router.post("/v1/embeddings")
async def route_embeddings(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_general_request(request, "/v1/embeddings", background_tasks)


@main_router.post("/tokenize")
async def route_tokenize(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_general_request(request, "/tokenize", background_tasks)


@main_router.post("/detokenize")
async def route_detokenize(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_general_request(request, "/detokenize", background_tasks)


@main_router.post("/v1/rerank")
async def route_v1_rerank(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_general_request(request, "/v1/rerank", background_tasks)


@main_router.post("/rerank")
async def route_rerank(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_general_request(request, "/rerank", background_tasks)


@main_router.post("/v1/score")
async def route_v1_score(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_general_request(request, "/v1/score", background_tasks)


@main_router.post("/score")
async def route_score(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_general_request(request, "/score", background_tasks)


@main_router.post("/sleep")
async def route_sleep(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_sleep_wakeup_request(request, "/sleep", background_tasks)


@main_router.post("/wake_up")
async def route_wake_up(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_sleep_wakeup_request(request, "/wake_up", background_tasks)


@main_router.get("/is_sleeping")
async def route_is_sleeping(request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())):
    return await route_sleep_wakeup_request(request, "/is_sleeping", background_tasks)


@main_router.get("/version")
async def show_version():
    ver = {"version": __version__}
    return JSONResponse(content=ver)


@main_router.get("/v1/models")
async def show_models():
    """
    Returns a list of all models available in the stack.

    Args:
        None

    Returns:
        JSONResponse: A JSON response containing the list of models and their relationships.

    Raises:
        Exception: If there is an error in retrieving the endpoint information.
    """
    endpoints = get_service_discovery().get_endpoint_info()
    existing_models = set()
    model_cards = []

    for endpoint in endpoints:
        if not endpoint.model_info:
            continue

        for model_id, model_info in endpoint.model_info.items():
            if model_id in existing_models:
                continue

            model_card = ModelCard(
                id=model_id,
                object="model",
                created=model_info.created,
                owned_by=model_info.owned_by,
                parent=model_info.parent,
            )
            model_cards.append(model_card)
            existing_models.add(model_id)

    model_list = ModelList(data=model_cards)
    return JSONResponse(content=model_list.model_dump())


@main_router.get("/engines")
async def get_engine_instances():
    """
    Returns a list of all models available in the stack.

    Args:
        None

    Returns:
        JSONResponse: A JSON response containing the list of models and their relationships.

    Raises:
        Exception: If there is an error in retrieving the endpoint information.
    """
    endpoints = get_service_discovery().get_endpoint_info()
    existing_engines = set()
    engines_cards = []

    for endpoint in endpoints:
        if endpoint.Id in existing_engines:
            continue
        engine_card = {
            "engine_id": endpoint.Id,
            "serving_models": endpoint.model_names,
            "created": endpoint.added_timestamp,
        }

        engines_cards.append(engine_card)
        existing_engines.add(endpoint.Id)

    return JSONResponse(content=engines_cards)


@main_router.get("/health")
async def health() -> Response:
    """
    Endpoint to check the health status of various components.

    This function verifies the health of the service discovery module and
    the engine stats scraper. If either component is down, it returns a
    503 response with the appropriate status message. If both components
    are healthy, it returns a 200 OK response.

    Returns:
        Response: A JSONResponse with status code 503 if a component is
        down, or a plain Response with status code 200 if all components
        are healthy.
    """

    if not get_service_discovery().get_health():
        return JSONResponse(
            content={"status": "Service discovery module is down."}, status_code=503
        )
    if not get_engine_stats_scraper().get_health():
        return JSONResponse(
            content={"status": "Engine stats scraper is down."}, status_code=503
        )

    return JSONResponse(content={"status": "healthy"}, status_code=200)


@main_router.post("/v1/audio/transcriptions")
async def route_v1_audio_transcriptions(
    request: Request, background_tasks: BackgroundTasks, _auth: None = Depends(require_user_token())
):
    """Handles audio transcription requests."""
    return await route_general_transcriptions(
        request, "/v1/audio/transcriptions", background_tasks
    )


@main_router.get("/v1/signature/{chat_id}")
async def get_signature(
    request: Request, chat_id: str, signing_algo: Optional[str] = None, _auth: None = Depends(require_user_token())
):
    """
    Get signature for chat_id of chat history.

    Args:
        request: The FastAPI request object
        chat_id: The chat ID to retrieve signature for
        signing_algo: Optional signing algorithm filter (ecdsa or ed25519)

    Returns:
        JSON response containing the signature data

    Raises:
        HTTPException: If chat_id is not found or signing algorithm is invalid
    """
    cache_value = get_chat(chat_id)
    if cache_value is None:
        raise HTTPException(status_code=404, detail="Chat id not found or expired")

    signature = None
    signing_algo = ECDSA if signing_algo is None else signing_algo

    # Retrieve the cached request and response
    try:
        value = json.loads(cache_value)
    except Exception as e:
        logger.error(f"Failed to parse the cache value: {cache_value} {e}")
        raise HTTPException(status_code=500, detail="Failed to parse the cache value")

    signing_address = None
    if signing_algo == ECDSA:
        signature = value.get("signature_ecdsa")
        signing_address = value.get("signing_address_ecdsa")
    elif signing_algo == ED25519:
        signature = value.get("signature_ed25519")
        signing_address = value.get("signing_address_ed25519")
    else:
        raise HTTPException(status_code=400, detail="Invalid signing algorithm")

    return dict(
        text=value.get("text"),
        signature=signature,
        signing_address=signing_address,
        signing_algo=signing_algo,
    )


@main_router.get("/v1/attestation/report")
async def attestation_report(
    request: Request,
    signing_algo: str | None = None,
    nonce: str | None = Query(None),
    signing_address: str | None = Query(None),
    _auth: None = Depends(require_user_token()),
):
    """
    Get attestation report of intel quote and nvidia payload.

    Args:
        request: The FastAPI request object
        signing_algo: The signing algorithm to use (ecdsa or ed25519). Defaults to ecdsa
        nonce: Optional nonce for the attestation. If not provided, a random one will be generated
        signing_address: Optional signing address to filter by. If provided, must match this server's address

    Returns:
        JSON response containing the attestation report

    Raises:
        HTTPException: If signing algorithm is invalid or signing address doesn't match
    """
    signing_algo = ECDSA if signing_algo is None else signing_algo
    if signing_algo not in [ECDSA, ED25519]:
        raise HTTPException(status_code=400, detail="Invalid signing algorithm")

    context = ecdsa_context if signing_algo == ECDSA else ed25519_context

    # If signing_address is specified and doesn't match this server's address, return 404
    if signing_address and context.signing_address.lower() != signing_address.lower():
        raise HTTPException(
            status_code=404, detail="Signing address not found on this server"
        )

    try:
        attestation = generate_attestation(context, nonce)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    resp = dict(attestation)
    resp["all_attestations"] = [attestation]
    return resp
