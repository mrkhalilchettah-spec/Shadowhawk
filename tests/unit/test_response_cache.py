"""
Response Cache Unit Tests
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License
"""

import pytest
from unittest.mock import Mock, patch

from shadowhawk.infrastructure.ai.response_cache import ResponseCache


def test_cache_initialization_disabled() -> None:
    """Test cache initialization when disabled"""
    cache = ResponseCache(enabled=False)
    
    assert not cache.enabled
    assert cache.client is None


@patch('shadowhawk.infrastructure.ai.response_cache.redis')
def test_cache_initialization_success(mock_redis: Mock) -> None:
    """Test successful cache initialization"""
    mock_client = Mock()
    mock_client.ping = Mock()
    mock_redis.from_url.return_value = mock_client
    
    cache = ResponseCache(redis_url="redis://localhost:6379", ttl=3600)
    
    assert cache.enabled
    assert cache.ttl == 3600
    mock_redis.from_url.assert_called_once()
    mock_client.ping.assert_called_once()


@patch('shadowhawk.infrastructure.ai.response_cache.redis')
def test_cache_initialization_failure(mock_redis: Mock) -> None:
    """Test cache initialization failure"""
    mock_redis.from_url.side_effect = Exception("Connection failed")
    
    cache = ResponseCache(redis_url="redis://localhost:6379")
    
    # Should fall back to disabled state
    assert not cache.enabled
    assert cache.client is None


def test_cache_get_when_disabled() -> None:
    """Test cache get when disabled"""
    cache = ResponseCache(enabled=False)
    
    result = cache.get(
        prompt="test",
        system_prompt="system",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
    )
    
    assert result is None


@patch('shadowhawk.infrastructure.ai.response_cache.redis')
def test_cache_get_miss(mock_redis: Mock) -> None:
    """Test cache miss"""
    mock_client = Mock()
    mock_client.ping = Mock()
    mock_client.get = Mock(return_value=None)
    mock_redis.from_url.return_value = mock_client
    
    cache = ResponseCache()
    result = cache.get(
        prompt="test prompt",
        system_prompt="system prompt",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
    )
    
    assert result is None
    assert cache.misses == 1
    assert cache.hits == 0


@patch('shadowhawk.infrastructure.ai.response_cache.redis')
def test_cache_get_hit(mock_redis: Mock) -> None:
    """Test cache hit"""
    mock_client = Mock()
    mock_client.ping = Mock()
    mock_client.get = Mock(return_value='{"content": "cached response"}')
    mock_redis.from_url.return_value = mock_client
    
    cache = ResponseCache()
    result = cache.get(
        prompt="test prompt",
        system_prompt="system prompt",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
    )
    
    assert result is not None
    assert result["content"] == "cached response"
    assert cache.hits == 1
    assert cache.misses == 0


def test_cache_set_when_disabled() -> None:
    """Test cache set when disabled"""
    cache = ResponseCache(enabled=False)
    
    # Should not raise exception
    cache.set(
        prompt="test",
        system_prompt="system",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
        response={"content": "test"},
    )


@patch('shadowhawk.infrastructure.ai.response_cache.redis')
def test_cache_set_success(mock_redis: Mock) -> None:
    """Test successful cache set"""
    mock_client = Mock()
    mock_client.ping = Mock()
    mock_client.setex = Mock()
    mock_redis.from_url.return_value = mock_client
    
    cache = ResponseCache(ttl=3600)
    cache.set(
        prompt="test prompt",
        system_prompt="system prompt",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
        response={"content": "test response"},
    )
    
    mock_client.setex.assert_called_once()
    args = mock_client.setex.call_args[0]
    assert args[1] == 3600  # TTL


@patch('shadowhawk.infrastructure.ai.response_cache.redis')
def test_cache_clear(mock_redis: Mock) -> None:
    """Test cache clear"""
    mock_client = Mock()
    mock_client.ping = Mock()
    mock_client.scan = Mock(side_effect=[
        (10, ["key1", "key2"]),
        (0, ["key3"]),
    ])
    mock_client.delete = Mock()
    mock_redis.from_url.return_value = mock_client
    
    cache = ResponseCache()
    cache.clear()
    
    assert mock_client.scan.call_count == 2
    assert mock_client.delete.call_count == 2


def test_cache_stats() -> None:
    """Test cache statistics"""
    cache = ResponseCache(enabled=False)
    cache.hits = 80
    cache.misses = 20
    
    stats = cache.get_stats()
    
    assert stats["enabled"] is False
    assert stats["hits"] == 80
    assert stats["misses"] == 20
    assert stats["total_requests"] == 100
    assert stats["hit_rate_percent"] == 80.0


def test_cache_reset_stats() -> None:
    """Test resetting cache statistics"""
    cache = ResponseCache(enabled=False)
    cache.hits = 100
    cache.misses = 50
    
    cache.reset_stats()
    
    assert cache.hits == 0
    assert cache.misses == 0


def test_cache_key_generation_consistency() -> None:
    """Test that same parameters generate same cache key"""
    cache = ResponseCache(enabled=False)
    
    key1 = cache._generate_key(
        prompt="test",
        system_prompt="system",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
    )
    
    key2 = cache._generate_key(
        prompt="test",
        system_prompt="system",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
    )
    
    assert key1 == key2


def test_cache_key_generation_different_params() -> None:
    """Test that different parameters generate different cache keys"""
    cache = ResponseCache(enabled=False)
    
    key1 = cache._generate_key(
        prompt="test1",
        system_prompt="system",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
    )
    
    key2 = cache._generate_key(
        prompt="test2",
        system_prompt="system",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
    )
    
    assert key1 != key2


@patch('shadowhawk.infrastructure.ai.response_cache.redis')
def test_cache_error_handling_get(mock_redis: Mock) -> None:
    """Test error handling in cache get"""
    mock_client = Mock()
    mock_client.ping = Mock()
    mock_client.get = Mock(side_effect=Exception("Redis error"))
    mock_redis.from_url.return_value = mock_client
    
    cache = ResponseCache()
    result = cache.get(
        prompt="test",
        system_prompt="system",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
    )
    
    # Should return None on error
    assert result is None


@patch('shadowhawk.infrastructure.ai.response_cache.redis')
def test_cache_error_handling_set(mock_redis: Mock) -> None:
    """Test error handling in cache set"""
    mock_client = Mock()
    mock_client.ping = Mock()
    mock_client.setex = Mock(side_effect=Exception("Redis error"))
    mock_redis.from_url.return_value = mock_client
    
    cache = ResponseCache()
    
    # Should not raise exception
    cache.set(
        prompt="test",
        system_prompt="system",
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000,
        response={"content": "test"},
    )
