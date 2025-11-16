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
import asyncio
import logging
import threading
from contextlib import asynccontextmanager

import sentry_sdk
import uvicorn
from fastapi import FastAPI

from aiohttp_client import AiohttpClientWrapper
from dynamic_config import (
    DynamicRouterConfig,
    get_dynamic_config_watcher,
    initialize_dynamic_config_watcher,
)
from experimental import get_feature_gates, initialize_feature_gates
from parsers.parser import parse_args
from routers.batches_router import batches_router
from routers.files_router import files_router
from routers.main_router import main_router
from routers.metrics_router import metrics_router
from routers.domain_registration_router import domain_registration_router
from routers.routing_logic import (
    get_routing_logic,
    initialize_routing_logic,
)
from service_discovery import (
    ServiceDiscoveryType,
    get_service_discovery,
    initialize_service_discovery,
)
from services.batch_service import initialize_batch_processor
from services.callbacks_service.callbacks import configure_custom_callbacks
from services.domain_registration_service import (
    initialize_domain_registration_service,
    cleanup_domain_registration_service,
    set_domain_registration_service,
    DomainRegistrationService,
)
from services.files_service import initialize_storage
from services.request_service.rewriter import (
    get_request_rewriter,
)
from stats.engine_stats import (
    get_engine_stats_scraper,
    initialize_engine_stats_scraper,
)
from stats.log_stats import log_stats
from stats.request_stats import (
    get_request_stats_monitor,
    initialize_request_stats_monitor,
)
from utils import (
    parse_comma_separated_args,
    parse_static_aliases,
    parse_static_urls,
    set_ulimit,
)

try:
    # Semantic cache integration
    from experimental.semantic_cache import (
        enable_semantic_cache,
        initialize_semantic_cache,
        is_semantic_cache_enabled,
    )
    from experimental.semantic_cache_integration import (
        semantic_cache_size,
    )

    semantic_cache_available = True
except ImportError:
    semantic_cache_available = False

logger = logging.getLogger("uvicorn")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.aiohttp_client_wrapper.start()
    if hasattr(app.state, "batch_processor"):
        await app.state.batch_processor.initialize()

    service_discovery = get_service_discovery()
    if hasattr(service_discovery, "initialize_client_sessions"):
        await service_discovery.initialize_client_sessions()

    app.state.event_loop = asyncio.get_event_loop()

    # Initialize domain registration service
    logger.info("Initializing domain registration service")
    domain_service = DomainRegistrationService()
    set_domain_registration_service(domain_service)
    domain_init_success = await initialize_domain_registration_service()
    if domain_init_success:
        logger.info("Domain registration service initialized successfully")
    else:
        logger.warning(
            "Domain registration service initialization failed, continuing without it"
        )

    yield

    # Cleanup domain registration service
    logger.info("Cleaning up domain registration service")
    await cleanup_domain_registration_service()

    await app.state.aiohttp_client_wrapper.stop()

    # Close the threaded-components
    logger.info("Closing engine stats scraper")
    engine_stats_scraper = get_engine_stats_scraper()
    engine_stats_scraper.close()

    logger.info("Closing service discovery module")
    service_discovery = get_service_discovery()
    service_discovery.close()

    # Close the optional dynamic config watcher
    dyn_cfg_watcher = get_dynamic_config_watcher()
    if dyn_cfg_watcher is not None:
        logger.info("Closing dynamic config watcher")
        dyn_cfg_watcher.close()


def initialize_all(app: FastAPI, args):
    """
    Initialize all the components of the router with the given arguments.

    Args:
        app (FastAPI): FastAPI application
        args: the parsed command-line arguments

    Raises:
        ValueError: if the configuration is invalid
    """
    if sentry_dsn := args.sentry_dsn:
        sentry_sdk.init(
            dsn=sentry_dsn,
            send_default_pii=True,
            profile_lifecycle="trace",
            traces_sample_rate=args.sentry_traces_sample_rate,
            profile_session_sample_rate=args.sentry_profile_session_sample_rate,
        )

    # Use simplified configuration
    config = args.config_obj

    # Initialize service discovery with backend list
    initialize_service_discovery(
        ServiceDiscoveryType.BACKEND_LIST,
        app=app,
        backends=config.backends,
        refresh_interval=config.refresh_interval,
        health_check_timeout_seconds=config.health_check_timeout_seconds,
    )

    # Initialize singletons via custom functions.
    initialize_engine_stats_scraper(30)  # Default interval
    initialize_request_stats_monitor(60)  # Default window

    # Initialize routing logic with simplified config
    initialize_routing_logic(
        config.routing_logic,
        session_key=config.session_key,
        lmcache_controller_port=9000,  # Default port
        prefill_model_labels=None,  # Not used in simplified config
        decode_model_labels=None,  # Not used in simplified config
        kv_aware_threshold=2000,  # Default threshold
    )

    # Initialize callbacks if specified
    if config.callbacks:
        configure_custom_callbacks(config.callbacks, app)

    # Initialize feature gates
    initialize_feature_gates(args.feature_gates)
    # Check if the SemanticCache feature gate is enabled
    feature_gates = get_feature_gates()
    if semantic_cache_available:
        if feature_gates.is_enabled("SemanticCache"):
            # The feature gate is enabled, explicitly enable the semantic cache
            enable_semantic_cache()

            # Verify that the semantic cache was successfully enabled
            if not is_semantic_cache_enabled():
                logger.error("Failed to enable semantic cache feature")

            logger.info("SemanticCache feature gate is enabled")

            # Initialize the semantic cache with the model if specified
            if args.semantic_cache_model:
                logger.info(
                    f"Initializing semantic cache with model: {args.semantic_cache_model}"
                )
                logger.info(
                    f"Semantic cache directory: {args.semantic_cache_dir or 'default'}"
                )
                logger.info(
                    f"Semantic cache threshold: {args.semantic_cache_threshold}"
                )

                cache = initialize_semantic_cache(
                    embedding_model=args.semantic_cache_model,
                    cache_dir=args.semantic_cache_dir,
                    default_similarity_threshold=args.semantic_cache_threshold,
                )

                # Update cache size metric
                if cache and hasattr(cache, "db") and hasattr(cache.db, "index"):
                    semantic_cache_size.labels(server="router").set(
                        cache.db.index.ntotal
                    )
                    logger.info(
                        f"Semantic cache initialized with {cache.db.index.ntotal} entries"
                    )

                logger.info(
                    f"Semantic cache initialized with model {args.semantic_cache_model}"
                )
            else:
                logger.warning(
                    "SemanticCache feature gate is enabled but no embedding model specified. "
                    "The semantic cache will not be functional without an embedding model. "
                    "Use --semantic-cache-model to specify an embedding model."
                )
        elif args.semantic_cache_model:
            logger.warning(
                "Semantic cache model specified but SemanticCache feature gate is not enabled. "
                "Enable the feature gate with --feature-gates=SemanticCache=true"
            )

    # --- Hybrid addition: attach singletons to FastAPI state ---
    app.state.engine_stats_scraper = get_engine_stats_scraper()
    app.state.request_stats_monitor = get_request_stats_monitor()
    app.state.router = get_routing_logic()
    app.state.request_rewriter = get_request_rewriter()


app = FastAPI(lifespan=lifespan)
app.include_router(main_router)
app.include_router(files_router)
app.include_router(batches_router)
app.include_router(metrics_router)
app.include_router(domain_registration_router)
app.state.aiohttp_client_wrapper = AiohttpClientWrapper()
app.state.semantic_cache_available = semantic_cache_available


def main():
    args = parse_args()
    initialize_all(app, args)

    # Use config from the config object
    config = args.config_obj

    if args.log_stats:
        threading.Thread(
            target=log_stats,
            args=(
                app,
                getattr(args, "log_stats_interval", 10),  # Default interval
            ),
            daemon=True,
        ).start()

    # Workaround to avoid footguns where uvicorn drops requests with too
    # many concurrent requests active.
    set_ulimit()
    uvicorn.run(app, host=config.host, port=config.port)


if __name__ == "__main__":
    main()
