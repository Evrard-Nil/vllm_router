import json
import time
from typing import Optional, Dict, Any
from threading import Lock
from log import init_logger

logger = init_logger(__name__)


class SimpleCache:
    """
    Simple in-memory cache for storing chat signatures.
    In a production environment, this could be replaced with Redis or another persistent store.
    """

    def __init__(self, ttl_seconds: int = 3600):  # 1 hour default TTL
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self._ttl_seconds = ttl_seconds

    def set_chat(self, chat_id: str, signature_data: str) -> None:
        """Store signature data for a chat ID."""
        with self._lock:
            self._cache[chat_id] = {"data": signature_data, "timestamp": time.time()}
            logger.debug(f"Cached signature for chat_id: {chat_id}")

    def get_chat(self, chat_id: str) -> Optional[str]:
        """Retrieve signature data for a chat ID."""
        with self._lock:
            if chat_id not in self._cache:
                return None

            entry = self._cache[chat_id]

            # Check if entry has expired
            if time.time() - entry["timestamp"] > self._ttl_seconds:
                del self._cache[chat_id]
                logger.debug(f"Expired cache entry for chat_id: {chat_id}")
                return None

            logger.debug(f"Retrieved signature for chat_id: {chat_id}")
            return entry["data"]

    def clear_expired(self) -> None:
        """Remove expired entries from the cache."""
        current_time = time.time()
        with self._lock:
            expired_keys = [
                key
                for key, entry in self._cache.items()
                if current_time - entry["timestamp"] > self._ttl_seconds
            ]
            for key in expired_keys:
                del self._cache[key]

            if expired_keys:
                logger.debug(f"Cleared {len(expired_keys)} expired cache entries")

    def size(self) -> int:
        """Get the current number of cached entries."""
        with self._lock:
            return len(self._cache)


# Global cache instance
_cache = SimpleCache()


def get_cache() -> SimpleCache:
    """Get the global cache instance."""
    return _cache


def set_chat(chat_id: str, signature_data: str) -> None:
    """Store signature data for a chat ID."""
    _cache.set_chat(chat_id, signature_data)


def get_chat(chat_id: str) -> Optional[str]:
    """Retrieve signature data for a chat ID."""
    return _cache.get_chat(chat_id)


def clear_expired() -> None:
    """Remove expired entries from the cache."""
    _cache.clear_expired()
