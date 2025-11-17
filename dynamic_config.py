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
from dataclasses import dataclass
from typing import List, Optional

from log import init_logger
from utils import parse_static_urls
from env_config import RouterConfig, load_config_from_env

logger = init_logger(__name__)


@dataclass
class DynamicRouterConfig:
    """
    Simplified configuration for the VLLM router.
    Configuration is loaded from environment variables only.
    Models are automatically discovered via the /v1/models endpoint.
    """

    # Required configurations
    backends: List[str]

    # Optional configurations
    routing_logic: str = "roundrobin"
    host: str = "0.0.0.0"
    port: int = 8001
    log_level: str = "info"
    refresh_interval: int = 30
    health_check_timeout_seconds: int = 10

    # Advanced options (rarely used)
    session_key: Optional[str] = None
    callbacks: Optional[str] = None

    @staticmethod
    def from_args(args) -> "DynamicRouterConfig":
        # For simplified config, we expect backends to be provided
        backends = getattr(args, "backends", [])
        if not backends:
            # Fallback to static backends for compatibility
            backends = parse_static_urls(getattr(args, "static_backends", ""))

        return DynamicRouterConfig(
            backends=backends,
            routing_logic=getattr(args, "routing_logic", "roundrobin"),
            host=getattr(args, "host", "0.0.0.0"),
            port=getattr(args, "port", 8001),
            log_level=getattr(args, "log_level", "info"),
            refresh_interval=getattr(args, "refresh_interval", 30),
            health_check_timeout_seconds=getattr(
                args, "health_check_timeout_seconds", 10
            ),
            session_key=getattr(args, "session_key", None),
            callbacks=getattr(args, "callbacks", None),
        )

    @staticmethod
    def from_env() -> "DynamicRouterConfig":
        """Create DynamicRouterConfig from environment variables."""
        env_config = load_config_from_env()
        config_dict = env_config.to_dict()
        return DynamicRouterConfig(**config_dict)

    def to_json_str(self) -> str:
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
