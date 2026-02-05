"""
Response Caching System
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License

Redis-based caching for LLM responses to reduce API costs.
"""

import json
import hashlib
import os
from typing import Optional, Dict, Any
import structlog

logger = structlog.get_logger()


class ResponseCache:
    """Cache LLM responses using Redis"""
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        ttl: Optional[int] = None,
        enabled: bool = True,
    ) -> None:
        """
        Initialize response cache
        
        Args:
            redis_url: Redis connection URL
            ttl: Time-to-live in seconds (default: 3600)
            enabled: Enable/disable caching
        """
        self.enabled = enabled
        self.ttl = ttl or int(os.getenv("REDIS_CACHE_TTL", "3600"))
        self.hits = 0
        self.misses = 0
        
        if not self.enabled:
            logger.info("response_cache_disabled")
            self.client = None
            return
        
        try:
            import redis
            redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379")
            self.client = redis.from_url(redis_url, decode_responses=True)
            self.client.ping()
            logger.info("response_cache_initialized", url=redis_url, ttl=self.ttl)
        except Exception as e:
            logger.warning(
                "redis_connection_failed",
                error=str(e),
                fallback="caching_disabled",
            )
            self.enabled = False
            self.client = None
    
    def _generate_key(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """
        Generate cache key from request parameters
        
        Args:
            prompt: User prompt
            system_prompt: System prompt
            model: Model name
            temperature: Temperature setting
            max_tokens: Max tokens setting
            
        Returns:
            Cache key string
        """
        # Create deterministic key from all parameters
        key_data = {
            "prompt": prompt,
            "system_prompt": system_prompt or "",
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        key_str = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.sha256(key_str.encode()).hexdigest()
        return f"llm_cache:{key_hash}"
    
    def get(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached response
        
        Args:
            prompt: User prompt
            system_prompt: System prompt
            model: Model name
            temperature: Temperature setting
            max_tokens: Max tokens setting
            
        Returns:
            Cached response or None
        """
        if not self.enabled or not self.client:
            return None
        
        key = self._generate_key(prompt, system_prompt, model, temperature, max_tokens)
        
        try:
            cached = self.client.get(key)
            if cached:
                self.hits += 1
                logger.debug("cache_hit", key=key)
                return json.loads(cached)
            else:
                self.misses += 1
                logger.debug("cache_miss", key=key)
                return None
        except Exception as e:
            logger.error("cache_get_error", error=str(e))
            return None
    
    def set(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: str,
        temperature: float,
        max_tokens: int,
        response: Dict[str, Any],
    ) -> None:
        """
        Cache response
        
        Args:
            prompt: User prompt
            system_prompt: System prompt
            model: Model name
            temperature: Temperature setting
            max_tokens: Max tokens setting
            response: LLM response to cache
        """
        if not self.enabled or not self.client:
            return
        
        key = self._generate_key(prompt, system_prompt, model, temperature, max_tokens)
        
        try:
            self.client.setex(
                key,
                self.ttl,
                json.dumps(response),
            )
            logger.debug("cache_set", key=key, ttl=self.ttl)
        except Exception as e:
            logger.error("cache_set_error", error=str(e))
    
    def clear(self) -> None:
        """Clear all cached responses"""
        if not self.enabled or not self.client:
            return
        
        try:
            # Find and delete all cache keys
            cursor = 0
            while True:
                cursor, keys = self.client.scan(cursor, match="llm_cache:*")
                if keys:
                    self.client.delete(*keys)
                if cursor == 0:
                    break
            logger.info("cache_cleared")
        except Exception as e:
            logger.error("cache_clear_error", error=str(e))
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics
        
        Returns:
            Dictionary with hit/miss counts and rates
        """
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        
        return {
            "enabled": self.enabled,
            "hits": self.hits,
            "misses": self.misses,
            "total_requests": total,
            "hit_rate_percent": round(hit_rate, 2),
        }
    
    def reset_stats(self) -> None:
        """Reset statistics counters"""
        self.hits = 0
        self.misses = 0
