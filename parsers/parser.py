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
import argparse
import logging
import sys

import utils
from dynamic_config import DynamicRouterConfig
from version import __version__

try:
    from experimental.semantic_cache_integration import (
        add_semantic_cache_args,
    )

    semantic_cache_available = True
except ImportError:
    semantic_cache_available = False


logger = logging.getLogger(__name__)


def verify_required_args_provided(args: argparse.Namespace) -> None:
    # Check if we have a valid config object
    if not hasattr(args, "config_obj") or not args.config_obj:
        logger.error(
            "No configuration available. Please configure environment variables (see .env.example)"
        )
        sys.exit(1)

    # Validate that the config has backends
    if not args.config_obj.backends:
        logger.error("Configuration must include at least one backend.")
        sys.exit(1)


def validate_static_model_types(model_types: str | None) -> None:
    if model_types is None:
        raise ValueError(
            "Static model types must be provided when using the backend healthcheck."
        )
    all_models = utils.ModelType.get_all_fields()
    for model_type in utils.parse_comma_separated_args(model_types):
        if model_type not in all_models:
            raise ValueError(
                f"The model type '{model_type}' is not supported. Supported model types are '{','.join(all_models)}'"
            )


# --- Argument Parsing and Initialization ---
def validate_args(args):
    verify_required_args_provided(args)

    # Validate session routing if specified
    if hasattr(args, "config_obj") and args.config_obj:
        if (
            args.config_obj.routing_logic == "session"
            and not args.config_obj.session_key
        ):
            raise ValueError(
                "Session key must be provided when using session routing logic."
            )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the vLLM Router. Configuration is loaded from environment variables only."
    )

    # Basic server settings (override environment variables)
    server_group = parser.add_argument_group(
        "Server Settings", "Basic server configuration (overrides environment variables)"
    )
    server_group.add_argument(
        "--host", type=str, default="0.0.0.0", help="The host to run the server on."
    )
    server_group.add_argument(
        "--port", type=int, default=8001, help="The port to run the server on."
    )
    server_group.add_argument(
        "--log-level",
        type=str,
        default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help="Log level for uvicorn. Default is 'info'.",
    )

    # Advanced options (rarely used)
    advanced_group = parser.add_argument_group(
        "Advanced Options", "Advanced configuration options"
    )
    advanced_group.add_argument(
        "--routing-logic",
        type=str,
        choices=[
            "roundrobin",
            "session",
            "kvaware",
            "prefixaware",
            "disaggregated_prefill",
        ],
        help="The routing logic to use (overrides config file)",
    )
    advanced_group.add_argument(
        "--session-key",
        type=str,
        default=None,
        help="The key (in the header) to identify a session.",
    )
    advanced_group.add_argument(
        "--callbacks",
        type=str,
        default=None,
        help="Path to the callback instance extending CustomCallbackHandler. Consists of file path without .py ending and instance variable name.",
    )

    # Legacy compatibility options (deprecated)
    legacy_group = parser.add_argument_group(
        "Legacy Options", "Deprecated options for backward compatibility"
    )
    legacy_group.add_argument(
        "--service-discovery",
        type=str,
        choices=["static", "url"],
        help=argparse.SUPPRESS,  # Hidden in help
    )
    legacy_group.add_argument(
        "--static-backends",
        type=str,
        default=None,
        help=argparse.SUPPRESS,  # Hidden in help
    )
    legacy_group.add_argument(
        "--static-models",
        type=str,
        default=None,
        help=argparse.SUPPRESS,  # Hidden in help
    )

    # Add --version argument
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
        help="Show version and exit",
    )

    # Temporarily disable semantic cache to isolate help string issue
    # if semantic_cache_available:
    #     add_semantic_cache_args(parser)

    # Add feature gates argument
    parser.add_argument(
        "--feature-gates",
        type=str,
        default="",
        help="Comma-separated list of feature gates (e.g., 'SemanticCache=true')",
    )

    # Monitoring options
    parser.add_argument(
        "--log-stats", action="store_true", help="Log statistics periodically."
    )
    parser.add_argument(
        "--log-stats-interval",
        type=int,
        default=10,
        help="The interval in seconds to log statistics.",
    )

    args = parser.parse_args()

    # Load configuration from environment variables
    logger.info("Loading configuration from environment variables")
    config = DynamicRouterConfig.from_env()

    # Override config with command line arguments if provided
    if args.host != "0.0.0.0":
        config.host = args.host
    if args.port != 8001:
        config.port = args.port
    if args.log_level != "info":
        config.log_level = args.log_level
    if args.routing_logic:
        config.routing_logic = args.routing_logic
    if args.session_key:
        config.session_key = args.session_key
    if args.callbacks:
        config.callbacks = args.callbacks

    # Store the config object for use by the application
    args.config_obj = config

    validate_args(args)
    return args
