"""
Environment configuration for vLLM router.
Handles all environment variable parsing and validation for Docker Compose deployment.
"""

import os
import logging
from typing import List, Optional, Union
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RouterConfig:
    """Main router configuration loaded from environment variables."""

    # Server settings
    host: str
    port: int
    log_level: str

    # Backend configuration
    backends: List[str]
    vllm_backends: List[str]
    router_backends: List[str]

    # Routing configuration
    routing_logic: str
    session_key: Optional[str]

    # Health and discovery settings
    refresh_interval: int
    health_check_timeout_seconds: int
    backend_detection_timeout: int

    # Advanced settings
    callbacks: Optional[str]
    max_router_hops: int

    # Monitoring settings
    log_stats: bool
    log_stats_interval: int

    # Feature gates
    feature_gates: str

    # Semantic cache settings
    semantic_cache_model: Optional[str]
    semantic_cache_dir: Optional[str]
    semantic_cache_threshold: float

    # Admin settings
    admin_token: Optional[str]

    @classmethod
    def from_env(cls) -> "RouterConfig":
        """Load configuration from environment variables."""
        return cls(
            # Server settings
            host=os.getenv("ROUTER_HOST", "0.0.0.0"),
            port=int(os.getenv("ROUTER_PORT", "8001")),
            log_level=os.getenv("ROUTER_LOG_LEVEL", "info"),
            # Backend configuration - support both formats
            backends=cls._parse_backends(os.getenv("BACKENDS", "")),
            vllm_backends=cls._parse_backends(os.getenv("VLLM_BACKENDS", "")),
            router_backends=cls._parse_backends(os.getenv("ROUTER_BACKENDS", "")),
            # Routing configuration
            routing_logic=os.getenv("ROUTING_LOGIC", "roundrobin"),
            session_key=os.getenv("SESSION_KEY"),
            # Health and discovery settings
            refresh_interval=int(os.getenv("REFRESH_INTERVAL", "30")),
            health_check_timeout_seconds=int(
                os.getenv("HEALTH_CHECK_TIMEOUT_SECONDS", "10")
            ),
            backend_detection_timeout=int(os.getenv("BACKEND_DETECTION_TIMEOUT", "10")),
            # Advanced settings
            callbacks=os.getenv("CALLBACKS"),
            max_router_hops=int(os.getenv("MAX_ROUTER_HOPS", "3")),
            # Monitoring settings
            log_stats=os.getenv("LOG_STATS", "false").lower() == "true",
            log_stats_interval=int(os.getenv("LOG_STATS_INTERVAL", "10")),
            # Feature gates
            feature_gates=os.getenv("FEATURE_GATES", ""),
            # Semantic cache settings
            semantic_cache_model=os.getenv("SEMANTIC_CACHE_MODEL"),
            semantic_cache_dir=os.getenv("SEMANTIC_CACHE_DIR"),
            semantic_cache_threshold=float(
                os.getenv("SEMANTIC_CACHE_THRESHOLD", "0.8")
            ),
            # Admin settings
            admin_token=os.getenv("ADMIN_TOKEN"),
        )

    @staticmethod
    def _parse_backends(backends_str: str) -> List[str]:
        """Parse comma-separated backends from environment variable."""
        if not backends_str:
            return []
        return [
            backend.strip() for backend in backends_str.split(",") if backend.strip()
        ]

    def get_effective_backends(self) -> List[str]:
        """Get the effective list of backends, combining all sources."""
        all_backends = []

        # Add general backends if specified
        if self.backends:
            all_backends.extend(self.backends)

        # Add VLLM backends if specified
        if self.vllm_backends:
            all_backends.extend(self.vllm_backends)

        # Add router backends if specified
        if self.router_backends:
            all_backends.extend(self.router_backends)

        # Remove duplicates while preserving order
        seen = set()
        unique_backends = []
        for backend in all_backends:
            if backend not in seen:
                seen.add(backend)
                unique_backends.append(backend)

        return unique_backends

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        # Validate server settings
        if self.port < 1 or self.port > 65535:
            errors.append("ROUTER_PORT must be between 1 and 65535")

        if self.log_level not in [
            "critical",
            "error",
            "warning",
            "info",
            "debug",
            "trace",
        ]:
            errors.append(
                "ROUTER_LOG_LEVEL must be one of: critical, error, warning, info, debug, trace"
            )

        # Validate routing logic
        valid_routing_logic = [
            "roundrobin",
            "session",
            "kvaware",
            "prefixaware",
            "disaggregated_prefill",
        ]
        if self.routing_logic not in valid_routing_logic:
            errors.append(
                f"ROUTING_LOGIC must be one of: {', '.join(valid_routing_logic)}"
            )

        # Validate session key for session routing
        if self.routing_logic == "session" and not self.session_key:
            errors.append("SESSION_KEY is required when ROUTING_LOGIC is 'session'")

        # Validate backends
        effective_backends = self.get_effective_backends()
        if not effective_backends:
            errors.append(
                "At least one backend must be specified via BACKENDS, VLLM_BACKENDS, or ROUTER_BACKENDS"
            )

        # Validate backend URLs
        for backend in effective_backends:
            if not backend.startswith(("http://", "https://")):
                errors.append(
                    f"Backend URL must start with http:// or https://: {backend}"
                )

        # Validate intervals
        if self.refresh_interval < 1:
            errors.append("REFRESH_INTERVAL must be at least 1 second")

        if self.health_check_timeout_seconds < 1:
            errors.append("HEALTH_CHECK_TIMEOUT_SECONDS must be at least 1 second")

        if self.backend_detection_timeout < 1:
            errors.append("BACKEND_DETECTION_TIMEOUT must be at least 1 second")

        # Validate monitoring settings
        if self.log_stats_interval < 1:
            errors.append("LOG_STATS_INTERVAL must be at least 1 second")

        # Validate semantic cache settings
        if self.semantic_cache_model and not (
            0.0 <= self.semantic_cache_threshold <= 1.0
        ):
            errors.append("SEMANTIC_CACHE_THRESHOLD must be between 0.0 and 1.0")

        # Validate max router hops
        if self.max_router_hops < 1:
            errors.append("MAX_ROUTER_HOPS must be at least 1")

        return errors

    def to_dict(self) -> dict:
        """Convert configuration to dictionary for compatibility with existing code."""
        return {
            "backends": self.get_effective_backends(),
            "host": self.host,
            "port": self.port,
            "log_level": self.log_level,
            "routing_logic": self.routing_logic,
            "session_key": self.session_key,
            "refresh_interval": self.refresh_interval,
            "health_check_timeout_seconds": self.health_check_timeout_seconds,
            "callbacks": self.callbacks,
        }

    def log_configuration(self):
        """Log the current configuration (without sensitive data)."""
        logger.info("Router configuration loaded from environment variables:")
        logger.info(f"  Host: {self.host}")
        logger.info(f"  Port: {self.port}")
        logger.info(f"  Log Level: {self.log_level}")
        logger.info(f"  Routing Logic: {self.routing_logic}")
        logger.info(f"  Backends: {len(self.get_effective_backends())} configured")
        logger.info(f"  Refresh Interval: {self.refresh_interval}s")
        logger.info(f"  Health Check Timeout: {self.health_check_timeout_seconds}s")
        logger.info(f"  Log Stats: {self.log_stats}")
        if self.semantic_cache_model:
            logger.info(
                f"  Semantic Cache: Enabled with model {self.semantic_cache_model}"
            )
        if self.admin_token:
            logger.info("  Admin Token: Configured")


def load_config_from_env() -> RouterConfig:
    """Load and validate router configuration from environment variables."""
    config = RouterConfig.from_env()

    # Validate configuration
    errors = config.validate()
    if errors:
        logger.error("Configuration validation failed:")
        for error in errors:
            logger.error(f"  - {error}")
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")

    # Log configuration
    config.log_configuration()

    return config


def is_env_config_enabled() -> bool:
    """Check if environment-based configuration is enabled."""
    return os.getenv("ROUTER_ENV_CONFIG", "true").lower() == "true"
