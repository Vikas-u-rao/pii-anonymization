"""
LLM Client abstraction for PII Gateway.
Supports OpenAI and can be extended for other providers.
"""

import logging
from typing import Optional, List, Dict, Any
from abc import ABC, abstractmethod
from openai import OpenAI, AsyncOpenAI
from openai import APIError, RateLimitError, APIConnectionError
import asyncio

from config import get_settings

logger = logging.getLogger(__name__)


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    @abstractmethod
    async def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> str:
        """Send chat messages and get response."""
        pass
    
    @abstractmethod
    def chat_sync(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> str:
        """Synchronous chat method."""
        pass


class OpenAIClient(BaseLLMClient):
    """
    OpenAI-compatible API client with retry logic and error handling.
    Supports OpenAI, Gemini, and other OpenAI-compatible providers.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        base_url: Optional[str] = None
    ):
        """
        Initialize OpenAI-compatible client.
        
        Args:
            api_key: API key (defaults to settings based on provider)
            model: Model name (defaults to settings based on provider)
            max_tokens: Max response tokens (defaults to settings)
            temperature: Sampling temperature (defaults to settings)
            base_url: Custom base URL for API (for Gemini, etc.)
        """
        settings = get_settings()
        provider = settings.llm_provider.lower()
        
        # Set defaults based on provider
        if provider == "gemini":
            self.api_key = api_key or settings.gemini_api_key
            self.model = model or settings.gemini_model
            self.base_url = base_url or settings.gemini_base_url
            logger.info(f"Using Gemini provider with model: {self.model}")
        else:  # openai
            self.api_key = api_key or settings.openai_api_key
            self.model = model or settings.openai_model
            self.base_url = base_url or settings.openai_base_url
            logger.info(f"Using OpenAI provider with model: {self.model}")
        
        self.max_tokens = max_tokens or settings.openai_max_tokens
        self.temperature = temperature or settings.openai_temperature
        
        if not self.api_key:
            logger.warning(f"{provider.upper()} API key not configured!")
        
        # Initialize clients with optional base_url
        client_kwargs = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        
        self.client = OpenAI(**client_kwargs) if self.api_key else None
        self.async_client = AsyncOpenAI(**client_kwargs) if self.api_key else None
    
    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> str:
        """
        Async chat completion with OpenAI.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Override default model
            max_tokens: Override default max tokens
            temperature: Override default temperature
            **kwargs: Additional parameters for OpenAI API
            
        Returns:
            Assistant's response text
            
        Raises:
            ValueError: If API key not configured
            APIError: If OpenAI API returns an error
        """
        if not self.async_client:
            raise ValueError("OpenAI API key not configured")
        
        try:
            response = await self.async_client.chat.completions.create(
                model=model or self.model,
                messages=messages,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature or self.temperature,
                **kwargs
            )
            
            content = response.choices[0].message.content
            logger.debug(f"OpenAI response received, tokens: {response.usage.total_tokens}")
            
            return content or ""
            
        except RateLimitError as e:
            logger.error(f"OpenAI rate limit exceeded: {e}")
            raise
        except APIConnectionError as e:
            logger.error(f"OpenAI connection error: {e}")
            raise
        except APIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise
    
    def chat_sync(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> str:
        """
        Synchronous chat completion with OpenAI.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Override default model
            max_tokens: Override default max tokens
            temperature: Override default temperature
            **kwargs: Additional parameters for OpenAI API
            
        Returns:
            Assistant's response text
        """
        if not self.client:
            raise ValueError("OpenAI API key not configured")
        
        try:
            response = self.client.chat.completions.create(
                model=model or self.model,
                messages=messages,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature or self.temperature,
                **kwargs
            )
            
            content = response.choices[0].message.content
            logger.debug(f"OpenAI response received, tokens: {response.usage.total_tokens}")
            
            return content or ""
            
        except RateLimitError as e:
            logger.error(f"OpenAI rate limit exceeded: {e}")
            raise
        except APIConnectionError as e:
            logger.error(f"OpenAI connection error: {e}")
            raise
        except APIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise
    
    async def chat_with_retry(
        self,
        messages: List[Dict[str, str]],
        max_retries: int = 3,
        base_delay: float = 1.0,
        **kwargs
    ) -> str:
        """
        Chat with exponential backoff retry.
        
        Args:
            messages: Chat messages
            max_retries: Maximum retry attempts
            base_delay: Base delay between retries
            **kwargs: Additional parameters
            
        Returns:
            Assistant's response text
        """
        last_error = None
        
        for attempt in range(max_retries):
            try:
                return await self.chat(messages, **kwargs)
                
            except RateLimitError as e:
                last_error = e
                delay = base_delay * (2 ** attempt)
                logger.warning(f"Rate limited, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                await asyncio.sleep(delay)
                
            except APIConnectionError as e:
                last_error = e
                delay = base_delay * (2 ** attempt)
                logger.warning(f"Connection error, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                await asyncio.sleep(delay)
        
        raise last_error or Exception("Max retries exceeded")


class MockLLMClient(BaseLLMClient):
    """
    Mock LLM client for testing and development.
    """
    
    def __init__(self, default_response: str = "This is a mock response."):
        """Initialize mock client with default response."""
        self.default_response = default_response
        self.call_history: List[Dict] = []
    
    async def chat(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> str:
        """Return mock response."""
        self.call_history.append({
            "messages": messages,
            "kwargs": kwargs
        })
        
        # Echo back user message with placeholders preserved
        user_message = messages[-1].get("content", "") if messages else ""
        return f"I received your message: {user_message}. {self.default_response}"
    
    def chat_sync(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> str:
        """Return mock response synchronously."""
        self.call_history.append({
            "messages": messages,
            "kwargs": kwargs
        })
        
        user_message = messages[-1].get("content", "") if messages else ""
        return f"I received your message: {user_message}. {self.default_response}"


# Singleton instances
_openai_client: Optional[OpenAIClient] = None
_mock_client: Optional[MockLLMClient] = None


def get_llm_client(use_mock: bool = False) -> BaseLLMClient:
    """
    Factory function to get LLM client.
    
    Args:
        use_mock: If True, return mock client for testing
        
    Returns:
        LLM client instance
    """
    global _openai_client, _mock_client
    
    if use_mock:
        if _mock_client is None:
            _mock_client = MockLLMClient()
        return _mock_client
    
    if _openai_client is None:
        _openai_client = OpenAIClient()
    
    return _openai_client
