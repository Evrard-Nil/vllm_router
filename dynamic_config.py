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
import threading
import time
from dataclasses import dataclass
from typing import List, Literal, Optional

from fastapi import FastAPI

from log import init_logger
from parsers.yaml_utils import (
    read_and_process_yaml_config_file,
)
from routers.routing_logic import reconfigure_routing_logic
from service_discovery import (
    ServiceDiscoveryType,
    reconfigure_service_discovery,
)
from services.callbacks_service.callbacks import configure_custom_callbacks
from utils import (
    SingletonMeta,
    parse_comma_separated_args,
    parse_static_aliases,
    parse_static_urls,
)

logger = init_logger(__name__)


@dataclass
class DynamicRouterConfig:
    """
    Simplified configuration for the VLLM router.
    Configuration is done through a YAML file with a list of backends.
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
    def from_yaml(yaml_path: str) -> "DynamicRouterConfig":
        config = read_and_process_yaml_config_file(yaml_path)
        return DynamicRouterConfig(**config)

    @staticmethod
    def from_json(json_path: str) -> "DynamicRouterConfig":
        with open(json_path, "r") as f:
            config = json.load(f)
        return DynamicRouterConfig(**config)

    def to_json_str(self) -> str:
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class DynamicConfigWatcher(metaclass=SingletonMeta):
    """
    Watches a config file for changes and updates the DynamicRouterConfig accordingly.
    """

    def __init__(
        self,
        config_path: str,
        config_file_type: Literal["YAML", "JSON"],
        watch_interval: int,
        init_config: DynamicRouterConfig,
        app: FastAPI,
    ):
        """
        Initializes the ConfigMapWatcher with the given ConfigMap name and namespace.

        Args:
            config_path: the path to the config file containing the dynamic configuration
            config_file_type: the config file type containing the dynamic configuration (YAML or JSON)
            watch_interval: the interval in seconds at which to watch the for changes
            app: the fastapi app to reconfigure
        """
        self.config_path = config_path
        self.config_file_type = config_file_type
        self.watch_interval = watch_interval
        self.current_config = init_config
        self.app = app

        # Watcher thread
        self.running = True
        self.watcher_thread = threading.Thread(target=self._watch_worker)
        self.watcher_thread.start()
        assert hasattr(self.app, "state")

    def get_current_config(self) -> DynamicRouterConfig:
        return self.current_config

    def reconfigure_service_discovery(self, config: DynamicRouterConfig):
        """
        Reconfigures the router with the given config using the simplified backend list approach.
        """
        reconfigure_service_discovery(
            ServiceDiscoveryType.BACKEND_LIST,
            app=self.app,
            backends=config.backends,
            refresh_interval=config.refresh_interval,
            health_check_timeout_seconds=config.health_check_timeout_seconds,
        )

        logger.info("DynamicConfigWatcher: Service discovery reconfiguration complete")

    def reconfigure_routing_logic(self, config: DynamicRouterConfig):
        """
        Reconfigures the router with the given config.
        """
        routing_logic = reconfigure_routing_logic(
            config.routing_logic, session_key=config.session_key
        )
        self.app.state.router = routing_logic
        logger.info("DynamicConfigWatcher: Routing logic reconfiguration complete")

    def reconfigure_batch_api(self, config: DynamicRouterConfig):
        """
        Reconfigures the router with the given config.
        """
        # TODO (ApostaC): Implement reconfigure_batch_api
        pass

    def reconfigure_stats(self, config: DynamicRouterConfig):
        """
        Reconfigures the router with the given config.
        """
        # TODO (ApostaC): Implement reconfigure_stats
        pass

    def reconfigure_callbacks(self, config: DynamicRouterConfig):
        """
        Reconfigures the router with the given config.
        """
        if config.callbacks:
            configure_custom_callbacks(config.callbacks, self.app)
        else:
            self.app.state.callbacks = None

    def reconfigure_all(self, config: DynamicRouterConfig):
        """
        Reconfigures the router with the given config.
        """
        self.reconfigure_service_discovery(config)
        self.reconfigure_routing_logic(config)
        self.reconfigure_batch_api(config)
        self.reconfigure_stats(config)
        self.reconfigure_callbacks(config)

    def _sleep_or_break(self, check_interval: float = 1):
        """
        Sleep for self.watch_interval seconds if self.running is True.
        Otherwise, break the loop.
        """
        for _ in range(int(self.watch_interval / check_interval)):
            if not self.running:
                break
            time.sleep(check_interval)

    def _watch_worker(self):
        """
        Watches the config file for changes and updates the DynamicRouterConfig accordingly.
        On every watch_interval, it will try loading the config file and compare the changes.
        If the config file has changed, it will reconfigure the system with the new config.
        """
        while self.running:
            try:
                if self.config_file_type == "YAML":
                    config = DynamicRouterConfig.from_yaml(self.config_path)
                elif self.config_file_type == "JSON":
                    config = DynamicRouterConfig.from_json(self.config_path)
                else:
                    raise ValueError("Unsupported config file type.")
                if config != self.current_config:
                    logger.info(
                        "DynamicConfigWatcher: Config changed, reconfiguring..."
                    )
                    self.reconfigure_all(config)
                    logger.info("DynamicConfigWatcher: Config reconfiguration complete")
                    self.current_config = config
            except Exception as e:
                logger.warning(f"DynamicConfigWatcher: Error loading config file: {e}")

            self._sleep_or_break()

    def close(self):
        """
        Closes the watcher thread.
        """
        self.running = False
        self.watcher_thread.join()
        logger.info("DynamicConfigWatcher: Closed")


def initialize_dynamic_config_watcher(
    config_path: str,
    config_file_type: Literal["YAML", "JSON"],
    watch_interval: int,
    init_config: DynamicRouterConfig,
    app: FastAPI,
):
    """
    Initializes the DynamicConfigWatcher with the given config path, file type and watch interval.
    """
    return DynamicConfigWatcher(
        config_path, config_file_type, watch_interval, init_config, app
    )


def get_dynamic_config_watcher() -> Optional[DynamicConfigWatcher]:
    """
    Returns the DynamicConfigWatcher singleton if it exists, None otherwise.
    """
    return DynamicConfigWatcher(_create=False)
