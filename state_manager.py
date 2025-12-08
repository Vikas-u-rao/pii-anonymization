"""
Redis-based State Manager for PII Mapping Storage.
Provides distributed, TTL-based storage for anonymization mappings.
"""

import json
import uuid
import redis
from typing import Dict, Optional, Tuple
from datetime import timedelta
import logging

from config import get_settings

logger = logging.getLogger(__name__)


class RedisStateManager:
    """
    Manages PII mapping state using Redis for distributed storage.
    
    Features:
    - TTL-based automatic cleanup
    - Request ID generation
    - Atomic operations
    - Connection pooling
    """
    
    def __init__(self):
        """Initialize Redis connection with settings."""
        settings = get_settings()
        
        self.redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        
        self.ttl_seconds = settings.redis_ttl_seconds
        self._prefix = "pii_gateway:"
    
    def _get_key(self, request_id: str) -> str:
        """Generate namespaced Redis key."""
        return f"{self._prefix}mapping:{request_id}"
    
    def generate_request_id(self) -> str:
        """
        Generate a unique request ID.
        
        Returns:
            UUID4 string for request identification.
        """
        return str(uuid.uuid4())
    
    def store_mapping(
        self, 
        request_id: str, 
        mapping: Dict[str, str],
        ttl_override: Optional[int] = None
    ) -> bool:
        """
        Store PII mapping in Redis with TTL.
        
        Args:
            request_id: Unique identifier for this request
            mapping: Dictionary of {placeholder: original_value}
            ttl_override: Optional custom TTL in seconds
            
        Returns:
            True if successful, False otherwise
        """
        try:
            key = self._get_key(request_id)
            ttl = ttl_override or self.ttl_seconds
            
            # Store as JSON string
            self.redis_client.setex(
                name=key,
                time=ttl,
                value=json.dumps(mapping)
            )
            
            logger.debug(f"Stored mapping for request {request_id}, TTL: {ttl}s")
            return True
            
        except redis.RedisError as e:
            logger.error(f"Failed to store mapping: {e}")
            return False
    
    def retrieve_mapping(self, request_id: str) -> Optional[Dict[str, str]]:
        """
        Retrieve PII mapping from Redis.
        
        Args:
            request_id: Unique identifier for the request
            
        Returns:
            Mapping dictionary if found, None otherwise
        """
        try:
            key = self._get_key(request_id)
            data = self.redis_client.get(key)
            
            if data:
                logger.debug(f"Retrieved mapping for request {request_id}")
                return json.loads(data)
            
            logger.warning(f"No mapping found for request {request_id}")
            return None
            
        except redis.RedisError as e:
            logger.error(f"Failed to retrieve mapping: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode mapping JSON: {e}")
            return None
    
    def delete_mapping(self, request_id: str) -> bool:
        """
        Delete PII mapping from Redis.
        
        Args:
            request_id: Unique identifier for the request
            
        Returns:
            True if deleted, False otherwise
        """
        try:
            key = self._get_key(request_id)
            result = self.redis_client.delete(key)
            
            logger.debug(f"Deleted mapping for request {request_id}: {bool(result)}")
            return bool(result)
            
        except redis.RedisError as e:
            logger.error(f"Failed to delete mapping: {e}")
            return False
    
    def extend_ttl(self, request_id: str, additional_seconds: int) -> bool:
        """
        Extend TTL for an existing mapping.
        
        Args:
            request_id: Unique identifier for the request
            additional_seconds: Seconds to add to current TTL
            
        Returns:
            True if successful, False otherwise
        """
        try:
            key = self._get_key(request_id)
            current_ttl = self.redis_client.ttl(key)
            
            if current_ttl > 0:
                new_ttl = current_ttl + additional_seconds
                self.redis_client.expire(key, new_ttl)
                logger.debug(f"Extended TTL for {request_id} to {new_ttl}s")
                return True
            
            return False
            
        except redis.RedisError as e:
            logger.error(f"Failed to extend TTL: {e}")
            return False
    
    def health_check(self) -> bool:
        """
        Check Redis connection health.
        
        Returns:
            True if Redis is reachable, False otherwise
        """
        try:
            return self.redis_client.ping()
        except redis.RedisError:
            return False
    
    def get_stats(self) -> Dict:
        """
        Get statistics about stored mappings.
        
        Returns:
            Dictionary with stats
        """
        try:
            pattern = f"{self._prefix}mapping:*"
            keys = self.redis_client.keys(pattern)
            
            return {
                "active_mappings": len(keys),
                "redis_connected": self.health_check(),
            }
        except redis.RedisError as e:
            logger.error(f"Failed to get stats: {e}")
            return {
                "active_mappings": -1,
                "redis_connected": False,
                "error": str(e)
            }


class InMemoryStateManager:
    """
    In-memory fallback state manager for development/testing.
    
    WARNING: Not suitable for production multi-server deployments!
    """
    
    def __init__(self):
        """Initialize in-memory storage."""
        self._storage: Dict[str, Dict[str, str]] = {}
        logger.warning("Using InMemoryStateManager - NOT suitable for production!")
    
    def generate_request_id(self) -> str:
        """Generate a unique request ID."""
        return str(uuid.uuid4())
    
    def store_mapping(
        self, 
        request_id: str, 
        mapping: Dict[str, str],
        ttl_override: Optional[int] = None
    ) -> bool:
        """Store mapping in memory."""
        self._storage[request_id] = mapping
        return True
    
    def retrieve_mapping(self, request_id: str) -> Optional[Dict[str, str]]:
        """Retrieve mapping from memory."""
        return self._storage.get(request_id)
    
    def delete_mapping(self, request_id: str) -> bool:
        """Delete mapping from memory."""
        if request_id in self._storage:
            del self._storage[request_id]
            return True
        return False
    
    def extend_ttl(self, request_id: str, additional_seconds: int) -> bool:
        """No-op for in-memory storage."""
        return request_id in self._storage
    
    def health_check(self) -> bool:
        """Always healthy for in-memory."""
        return True
    
    def get_stats(self) -> Dict:
        """Get storage statistics."""
        return {
            "active_mappings": len(self._storage),
            "redis_connected": False,
            "mode": "in_memory"
        }


def get_state_manager():
    """
    Factory function to get appropriate state manager.
    
    Tries Redis first, falls back to in-memory if Redis unavailable.
    """
    try:
        manager = RedisStateManager()
        if manager.health_check():
            logger.info("Using Redis state manager")
            return manager
    except Exception as e:
        logger.warning(f"Redis unavailable: {e}")
    
    logger.warning("Falling back to in-memory state manager")
    return InMemoryStateManager()
