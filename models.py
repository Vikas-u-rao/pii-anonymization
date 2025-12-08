"""
Pydantic models for API request/response validation.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from enum import Enum


class ChatRole(str, Enum):
    """Chat message roles."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class ChatMessage(BaseModel):
    """Single chat message."""
    role: ChatRole = Field(..., description="Message role")
    content: str = Field(..., description="Message content")


class ChatRequest(BaseModel):
    """Request model for /chat endpoint."""
    message: str = Field(
        ..., 
        description="User message to send to LLM",
        min_length=1,
        max_length=10000
    )
    system_prompt: Optional[str] = Field(
        default=None,
        description="Optional system prompt"
    )
    model: Optional[str] = Field(
        default=None,
        description="Override default model"
    )
    temperature: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=2.0,
        description="Sampling temperature"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Hello, I am Rohan. My phone is 9876543210.",
                "system_prompt": "You are a helpful assistant."
            }
        }


class EntityInfo(BaseModel):
    """Information about a detected PII entity."""
    type: str = Field(..., description="Entity type (e.g., PERSON, PHONE_NUMBER)")
    placeholder: str = Field(..., description="Placeholder used in anonymized text")
    confidence: float = Field(..., description="Detection confidence score")


class ChatResponse(BaseModel):
    """Response model for /chat endpoint."""
    request_id: str = Field(..., description="Unique request identifier")
    original_message: str = Field(..., description="Original user message")
    anonymized_message: str = Field(..., description="Message sent to LLM")
    llm_response: str = Field(..., description="Raw LLM response")
    final_response: str = Field(..., description="De-anonymized response")
    entities_detected: List[EntityInfo] = Field(
        default_factory=list,
        description="List of PII entities detected"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "request_id": "550e8400-e29b-41d4-a716-446655440000",
                "original_message": "Hello, I am Rohan. My phone is 9876543210.",
                "anonymized_message": "Hello, I am [PERSON_1]. My phone is [PHONE_NUMBER_1].",
                "llm_response": "Hello [PERSON_1], I've noted your phone [PHONE_NUMBER_1].",
                "final_response": "Hello Rohan, I've noted your phone 9876543210.",
                "entities_detected": [
                    {"type": "PERSON", "placeholder": "[PERSON_1]", "confidence": 0.85},
                    {"type": "PHONE_NUMBER", "placeholder": "[PHONE_NUMBER_1]", "confidence": 0.9}
                ]
            }
        }


class AnonymizeRequest(BaseModel):
    """Request model for /anonymize endpoint."""
    text: str = Field(
        ...,
        description="Text to anonymize",
        min_length=1,
        max_length=50000
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "text": "My name is Rohan and my PAN is ABCDE1234F."
            }
        }


class AnonymizeResponse(BaseModel):
    """Response model for /anonymize endpoint."""
    request_id: str = Field(..., description="Request ID for later de-anonymization")
    original_text: str = Field(..., description="Original input text")
    anonymized_text: str = Field(..., description="Anonymized text")
    entities: List[EntityInfo] = Field(
        default_factory=list,
        description="Detected PII entities"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "request_id": "550e8400-e29b-41d4-a716-446655440000",
                "original_text": "My name is Rohan and my PAN is ABCDE1234F.",
                "anonymized_text": "My name is [PERSON_1] and my PAN is [IN_PAN_1].",
                "entities": [
                    {"type": "PERSON", "placeholder": "[PERSON_1]", "confidence": 0.85},
                    {"type": "IN_PAN", "placeholder": "[IN_PAN_1]", "confidence": 0.9}
                ]
            }
        }


class DeAnonymizeRequest(BaseModel):
    """Request model for /deanonymize endpoint."""
    request_id: str = Field(..., description="Request ID from anonymization")
    text: str = Field(..., description="Text with placeholders to restore")
    
    class Config:
        json_schema_extra = {
            "example": {
                "request_id": "550e8400-e29b-41d4-a716-446655440000",
                "text": "Hello [PERSON_1], your PAN [IN_PAN_1] is verified."
            }
        }


class DeAnonymizeResponse(BaseModel):
    """Response model for /deanonymize endpoint."""
    original_text: str = Field(..., description="Text with placeholders restored")
    
    class Config:
        json_schema_extra = {
            "example": {
                "original_text": "Hello Rohan, your PAN ABCDE1234F is verified."
            }
        }


class HealthResponse(BaseModel):
    """Response model for /health endpoint."""
    status: str = Field(..., description="Service status")
    redis_connected: bool = Field(..., description="Redis connection status")
    active_mappings: int = Field(..., description="Number of active mappings")
    supported_entities: List[str] = Field(
        default_factory=list,
        description="List of supported entity types"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "redis_connected": True,
                "active_mappings": 42,
                "supported_entities": ["PERSON", "PHONE_NUMBER", "EMAIL", "IN_PAN"]
            }
        }


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    request_id: Optional[str] = Field(None, description="Request ID if available")
    
    class Config:
        json_schema_extra = {
            "example": {
                "error": "ValidationError",
                "message": "Message cannot be empty",
                "request_id": None
            }
        }
