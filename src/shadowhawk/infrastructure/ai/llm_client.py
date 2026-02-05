"""
LLM Client Wrapper
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License

Provides unified interface for OpenAI and Anthropic LLM APIs with cost tracking,
error handling, and rate limiting.
"""

import os
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum
import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

logger = structlog.get_logger()


class LLMProvider(str, Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class LLMUsageStats:
    """Track LLM usage and costs"""
    
    def __init__(self) -> None:
        self.total_tokens = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_cost = 0.0
        self.requests = 0
        self.errors = 0
        
    def add_usage(
        self, 
        prompt_tokens: int, 
        completion_tokens: int, 
        cost: float
    ) -> None:
        """Add usage statistics"""
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self.total_tokens += prompt_tokens + completion_tokens
        self.total_cost += cost
        self.requests += 1
        
    def add_error(self) -> None:
        """Increment error count"""
        self.errors += 1
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_tokens": self.total_tokens,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_cost": self.total_cost,
            "requests": self.requests,
            "errors": self.errors,
        }


class LLMClient:
    """Unified LLM client for OpenAI and Anthropic"""
    
    # Pricing per 1K tokens (as of 2024)
    PRICING = {
        LLMProvider.OPENAI: {
            "gpt-4-turbo-preview": {"prompt": 0.01, "completion": 0.03},
            "gpt-4": {"prompt": 0.03, "completion": 0.06},
            "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
        },
        LLMProvider.ANTHROPIC: {
            "claude-3-opus-20240229": {"prompt": 0.015, "completion": 0.075},
            "claude-3-sonnet-20240229": {"prompt": 0.003, "completion": 0.015},
            "claude-3-haiku-20240307": {"prompt": 0.00025, "completion": 0.00125},
        },
    }
    
    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> None:
        """
        Initialize LLM client
        
        Args:
            provider: LLM provider (openai or anthropic)
            api_key: API key (defaults to env variable)
            model: Model name (defaults to env variable)
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
        """
        self.provider = provider or LLMProvider(
            os.getenv("LLM_PROVIDER", "openai")
        )
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.stats = LLMUsageStats()
        
        # Initialize the appropriate client
        if self.provider == LLMProvider.OPENAI:
            import openai
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            if not self.api_key:
                raise ValueError("OPENAI_API_KEY not set")
            self.model = model or os.getenv(
                "OPENAI_MODEL", "gpt-4-turbo-preview"
            )
            self.client = openai.OpenAI(api_key=self.api_key)
            
        elif self.provider == LLMProvider.ANTHROPIC:
            import anthropic
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
            if not self.api_key:
                raise ValueError("ANTHROPIC_API_KEY not set")
            self.model = model or os.getenv(
                "ANTHROPIC_MODEL", "claude-3-opus-20240229"
            )
            self.client = anthropic.Anthropic(api_key=self.api_key)
            
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
            
        logger.info(
            "llm_client_initialized",
            provider=self.provider.value,
            model=self.model,
        )
    
    def _calculate_cost(
        self, 
        prompt_tokens: int, 
        completion_tokens: int
    ) -> float:
        """Calculate cost based on token usage"""
        pricing = self.PRICING.get(self.provider, {}).get(self.model, {})
        if not pricing:
            logger.warning(
                "pricing_not_found",
                provider=self.provider,
                model=self.model,
            )
            return 0.0
            
        prompt_cost = (prompt_tokens / 1000) * pricing["prompt"]
        completion_cost = (completion_tokens / 1000) * pricing["completion"]
        return prompt_cost + completion_cost
    
    @retry(
        retry=retry_if_exception_type((Exception,)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Generate completion from LLM
        
        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            max_tokens: Override max tokens
            temperature: Override temperature
            
        Returns:
            Dict with response, usage stats, and metadata
        """
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature or self.temperature
        
        try:
            if self.provider == LLMProvider.OPENAI:
                return await self._complete_openai(
                    prompt, system_prompt, max_tokens, temperature
                )
            elif self.provider == LLMProvider.ANTHROPIC:
                return await self._complete_anthropic(
                    prompt, system_prompt, max_tokens, temperature
                )
        except Exception as e:
            self.stats.add_error()
            logger.error(
                "llm_completion_error",
                provider=self.provider,
                error=str(e),
            )
            raise
    
    async def _complete_openai(
        self,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> Dict[str, Any]:
        """Complete using OpenAI API"""
        messages: List[Dict[str, str]] = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        
        # Extract usage and calculate cost
        usage = response.usage
        prompt_tokens = usage.prompt_tokens if usage else 0
        completion_tokens = usage.completion_tokens if usage else 0
        cost = self._calculate_cost(prompt_tokens, completion_tokens)
        
        self.stats.add_usage(prompt_tokens, completion_tokens, cost)
        
        content = response.choices[0].message.content or ""
        
        logger.info(
            "openai_completion_success",
            model=self.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost=cost,
        )
        
        return {
            "content": content,
            "provider": self.provider.value,
            "model": self.model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "cost": cost,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    async def _complete_anthropic(
        self,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> Dict[str, Any]:
        """Complete using Anthropic API"""
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        
        response = self.client.messages.create(**kwargs)
        
        # Extract usage and calculate cost
        usage = response.usage
        prompt_tokens = usage.input_tokens
        completion_tokens = usage.output_tokens
        cost = self._calculate_cost(prompt_tokens, completion_tokens)
        
        self.stats.add_usage(prompt_tokens, completion_tokens, cost)
        
        content = response.content[0].text if response.content else ""
        
        logger.info(
            "anthropic_completion_success",
            model=self.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost=cost,
        )
        
        return {
            "content": content,
            "provider": self.provider.value,
            "model": self.model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "cost": cost,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics"""
        return self.stats.to_dict()
    
    def reset_stats(self) -> None:
        """Reset usage statistics"""
        self.stats = LLMUsageStats()
