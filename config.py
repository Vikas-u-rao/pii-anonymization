"""
Configuration management for PII Anonymization Gateway.
Uses Pydantic Settings for type-safe environment variable handling.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # App Settings
    app_name: str = "PII Anonymization Gateway"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # LLM Provider Settings ("openai" or "gemini")
    llm_provider: str = "gemini"
    
    # OpenAI Settings
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    openai_max_tokens: int = 1000
    openai_temperature: float = 0.7
    openai_base_url: Optional[str] = None  # Custom base URL
    
    # Gemini Settings (uses OpenAI-compatible API)
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash-lite"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai/"
    
    # Redis Settings
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: Optional[str] = None
    redis_db: int = 0
    redis_ttl_seconds: int = 3600  # 1 hour TTL for mappings
    
    # Presidio Settings
    presidio_language: str = "en"
    presidio_score_threshold: float = 0.5
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Cached settings instance.
    Uses lru_cache to avoid re-reading env vars on every request.
    """
    return Settings()
