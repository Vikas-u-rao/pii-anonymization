"""
PII Anonymization Gateway - FastAPI Application.
Production-ready REST API for PII detection, anonymization, and LLM proxying.
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from config import get_settings, Settings
from models import (
    ChatRequest, ChatResponse,
    AnonymizeRequest, AnonymizeResponse,
    DeAnonymizeRequest, DeAnonymizeResponse,
    HealthResponse, ErrorResponse, EntityInfo
)
from anonymizer_engine import get_anonymizer, PIIAnonymizer
from state_manager import get_state_manager, RedisStateManager, InMemoryStateManager
from llm_client import get_llm_client, BaseLLMClient
from middleware import (
    limiter, 
    RequestLoggingMiddleware, 
    SecurityHeadersMiddleware
)
from security import (
    get_injection_detector,
    get_content_filter,
    InputValidator
)
from logging_config import setup_logging, get_audit_logger

# Configure structured logging
logger = setup_logging()


# === Lifespan Management ===

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Starting PII Anonymization Gateway...")
    
    settings = get_settings()
    logger.info(f"App: {settings.app_name} v{settings.app_version}")
    logger.info(f"Debug mode: {settings.debug}")
    
    # Pre-initialize components
    anonymizer = get_anonymizer()
    logger.info(f"Loaded {len(anonymizer.get_supported_entities())} entity types")
    
    state_manager = get_state_manager()
    logger.info(f"State manager: {type(state_manager).__name__}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down PII Anonymization Gateway...")


# === FastAPI App ===

app = FastAPI(
    title="PII Anonymization Gateway",
    description="""
    A middleware service that sits between users and LLMs to protect sensitive data.
    
    ## Features
    
    - **PII Detection**: Automatically detects names, phone numbers, emails, IDs, and more
    - **Indian PII Support**: Recognizes PAN, Aadhaar, IFSC, GST, and other Indian identifiers
    - **Reversible Anonymization**: Replaces PII with indexed placeholders, restores them in responses
    - **Redis State Management**: Distributed mapping storage with TTL for scalability
    - **LLM Integration**: Proxies requests to OpenAI with automatic PII protection
    
    ## Architecture
    
    ```
    User → [Original Message] → Gateway → [Anonymized Message] → LLM
                                    ↓
                              Redis (mapping)
                                    ↓
    User ← [Restored Response] ← Gateway ← [Raw Response] ← LLM
    ```
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom middleware
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting middleware
app.add_middleware(SlowAPIMiddleware)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# === Dependencies ===

def get_settings_dep() -> Settings:
    """Dependency for settings."""
    return get_settings()


def get_anonymizer_dep() -> PIIAnonymizer:
    """Dependency for anonymizer."""
    return get_anonymizer()


def get_state_manager_dep():
    """Dependency for state manager."""
    return get_state_manager()


def get_llm_client_dep() -> BaseLLMClient:
    """Dependency for LLM client."""
    settings = get_settings()
    # Use mock if no API key configured
    use_mock = not settings.openai_api_key
    if use_mock:
        logger.warning("No OpenAI API key - using mock client")
    return get_llm_client(use_mock=use_mock)


# === Exception Handlers ===

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error="HTTPError",
            message=exc.detail,
            request_id=None
        ).model_dump()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="InternalError",
            message="An unexpected error occurred",
            request_id=None
        ).model_dump()
    )


# === API Endpoints ===

@app.get("/", tags=["Info"])
async def root():
    """Root endpoint with service info."""
    settings = get_settings()
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(
    anonymizer: PIIAnonymizer = Depends(get_anonymizer_dep),
    state_manager = Depends(get_state_manager_dep)
):
    """
    Check service health and component status.
    
    Returns:
        Health status including Redis connection and supported entities
    """
    stats = state_manager.get_stats()
    
    return HealthResponse(
        status="healthy",
        redis_connected=stats.get("redis_connected", False),
        active_mappings=stats.get("active_mappings", 0),
        supported_entities=anonymizer.get_supported_entities()
    )


@app.post("/chat", response_model=ChatResponse, tags=["Chat"])
async def chat(
    request: ChatRequest,
    http_request: Request,
    anonymizer: PIIAnonymizer = Depends(get_anonymizer_dep),
    state_manager = Depends(get_state_manager_dep),
    llm_client: BaseLLMClient = Depends(get_llm_client_dep),
    settings: Settings = Depends(get_settings_dep)
):
    """
    Send a message to LLM with automatic PII anonymization.
    
    Flow:
    1. Validate input and check for prompt injection
    2. Detect and anonymize PII in user message
    3. Store mapping in Redis with TTL
    4. Send anonymized message to LLM
    5. De-anonymize LLM response
    6. Return both versions for transparency
    
    Args:
        request: Chat request with user message
        
    Returns:
        Chat response with original, anonymized, and restored versions
    """
    # Input validation
    is_valid, error_msg = InputValidator.validate_message(request.message)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)
    
    # Prompt injection detection
    injection_detector = get_injection_detector()
    is_suspicious, patterns = injection_detector.detect(request.message)
    if is_suspicious:
        logger.warning(f"Prompt injection attempt detected from {http_request.client.host}")
        raise HTTPException(
            status_code=400, 
            detail="Message contains suspicious content patterns"
        )
    
    # Content filtering
    content_filter = get_content_filter()
    should_block, reason = content_filter.should_block(request.message)
    if should_block:
        raise HTTPException(status_code=400, detail=reason)
    
    # Generate request ID
    request_id = state_manager.generate_request_id()
    logger.info(f"Processing chat request: {request_id}")
    
    try:
        # Step 1: Anonymize
        anon_result = anonymizer.anonymize(request.message)
        
        # Step 2: Store mapping
        state_manager.store_mapping(request_id, anon_result.mapping)
        
        # Step 3: Build messages for LLM
        messages = []
        
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        
        messages.append({"role": "user", "content": anon_result.anonymized_text})
        
        # Step 4: Call LLM
        llm_response = await llm_client.chat(
            messages=messages,
            model=request.model,
            temperature=request.temperature
        )
        
        # Step 5: De-anonymize response
        final_response = anonymizer.de_anonymize(llm_response, anon_result.mapping)
        
        # Build entity info
        entities = [
            EntityInfo(
                type=e["type"],
                placeholder=e["placeholder"],
                confidence=e["confidence"]
            )
            for e in anon_result.entities_found
        ]
        
        logger.info(f"Chat completed: {request_id}, entities: {len(entities)}")
        
        # Audit log (no PII)
        audit_logger = get_audit_logger()
        audit_logger.log_anonymization(
            request_id=request_id,
            entity_types=[e.type for e in entities],
            entity_count=len(entities),
            text_length=len(request.message),
            source_ip=http_request.client.host if http_request.client else None
        )
        
        return ChatResponse(
            request_id=request_id,
            original_message=request.message,
            anonymized_message=anon_result.anonymized_text,
            llm_response=llm_response,
            final_response=final_response,
            entities_detected=entities
        )
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to process chat request")


@app.post("/anonymize", response_model=AnonymizeResponse, tags=["Anonymization"])
async def anonymize_text(
    request: AnonymizeRequest,
    http_request: Request,
    anonymizer: PIIAnonymizer = Depends(get_anonymizer_dep),
    state_manager = Depends(get_state_manager_dep)
):
    """
    Anonymize PII in text without sending to LLM.
    
    Useful for:
    - Pre-processing text before custom LLM calls
    - Batch anonymization
    - Testing detection capabilities
    
    Args:
        request: Text to anonymize
        
    Returns:
        Anonymized text with request ID for later de-anonymization
    """
    request_id = state_manager.generate_request_id()
    
    # Anonymize
    result = anonymizer.anonymize(request.text)
    
    # Store mapping
    state_manager.store_mapping(request_id, result.mapping)
    
    # Build entity info
    entities = [
        EntityInfo(
            type=e["type"],
            placeholder=e["placeholder"],
            confidence=e["confidence"]
        )
        for e in result.entities_found
    ]
    
    logger.info(f"Anonymized text: {request_id}, entities: {len(entities)}")
    
    return AnonymizeResponse(
        request_id=request_id,
        original_text=request.text,
        anonymized_text=result.anonymized_text,
        entities=entities
    )


@app.post("/deanonymize", response_model=DeAnonymizeResponse, tags=["Anonymization"])
async def deanonymize_text(
    request: DeAnonymizeRequest,
    anonymizer: PIIAnonymizer = Depends(get_anonymizer_dep),
    state_manager = Depends(get_state_manager_dep)
):
    """
    Restore original values from anonymized text.
    
    Requires the request_id from a previous /anonymize call.
    Mapping is stored in Redis with TTL.
    
    Args:
        request: Request ID and text with placeholders
        
    Returns:
        Text with placeholders replaced by original values
    """
    # Retrieve mapping
    mapping = state_manager.retrieve_mapping(request.request_id)
    
    if mapping is None:
        raise HTTPException(
            status_code=404,
            detail=f"No mapping found for request_id: {request.request_id}. "
                   f"Mapping may have expired (TTL: {get_settings().redis_ttl_seconds}s)"
        )
    
    # De-anonymize
    restored_text = anonymizer.de_anonymize(request.text, mapping)
    
    logger.info(f"De-anonymized text for: {request.request_id}")
    
    return DeAnonymizeResponse(original_text=restored_text)


@app.get("/entities", tags=["Info"])
async def list_entities(
    anonymizer: PIIAnonymizer = Depends(get_anonymizer_dep)
):
    """
    List all supported PII entity types.
    
    Returns:
        List of entity type names that can be detected
    """
    entities = anonymizer.get_supported_entities()
    
    return {
        "count": len(entities),
        "entities": sorted(entities)
    }


@app.delete("/mapping/{request_id}", tags=["Anonymization"])
async def delete_mapping(
    request_id: str,
    state_manager = Depends(get_state_manager_dep)
):
    """
    Manually delete a mapping before TTL expiration.
    
    Useful for:
    - Compliance requirements (immediate data deletion)
    - Cleanup after processing
    
    Args:
        request_id: The request ID to delete
        
    Returns:
        Deletion status
    """
    deleted = state_manager.delete_mapping(request_id)
    
    if deleted:
        logger.info(f"Deleted mapping: {request_id}")
        return {"status": "deleted", "request_id": request_id}
    else:
        raise HTTPException(
            status_code=404,
            detail=f"No mapping found for request_id: {request_id}"
        )


# === Main Entry ===

if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info"
    )
