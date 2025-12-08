# GitHub Copilot Instructions for PII Anonymization Gateway

This document provides GitHub Copilot with context and guidelines for working with this project effectively.

## Project Overview

This is a **PII Anonymization Gateway** - a production-ready middleware service that protects sensitive Personal Identifiable Information (PII) when interacting with LLMs (Large Language Models) like OpenAI/Claude.

### Core Purpose
- Detect PII in user messages before sending to LLMs
- Replace PII with indexed placeholders (e.g., `[PERSON_1]`, `[IN_PAN_1]`)
- Restore original PII in LLM responses
- Ensure HIPAA-like compliance for sensitive data processing

### Technology Stack
- **Language**: Python 3.13+
- **Framework**: FastAPI with async/await patterns
- **PII Detection**: Microsoft Presidio (Analyzer + Anonymizer)
- **NLP Model**: spaCy `en_core_web_lg`
- **State Management**: Redis (primary) with InMemory fallback
- **Rate Limiting**: SlowAPI with middleware approach
- **Testing**: pytest with async fixtures
- **Containerization**: Docker + Docker Compose

## Project Structure

```
hipaa-bypass/
├── main.py              # FastAPI app entry point, lifespan, endpoints
├── config.py            # Pydantic Settings configuration
├── models.py            # Pydantic request/response models
├── anonymizer_engine.py # Core PII detection and anonymization logic
├── recognizers.py       # Custom Indian PII recognizers (PAN, Aadhaar, etc.)
├── state_manager.py     # Redis/InMemory state management
├── llm_client.py        # OpenAI client abstraction
├── middleware.py        # Rate limiting, logging, security headers
├── security.py          # Input validation, injection detection
├── logging_config.py    # Structured logging setup
└── tests/
    └── test_gateway.py  # Comprehensive test suite (28 tests)
```

## Coding Standards

### Python Style
- Follow PEP 8 conventions
- Use type hints for all function signatures
- Write docstrings for all public functions and classes (Google style)
- Use f-strings for string formatting
- Prefer `async/await` for I/O operations

### Example Function Signature
```python
async def process_message(
    message: str,
    settings: Settings,
    anonymizer: PIIAnonymizer
) -> tuple[str, dict[str, str]]:
    """
    Process a message and anonymize PII.
    
    Args:
        message: The input text to process
        settings: Application settings
        anonymizer: The PII anonymizer instance
        
    Returns:
        A tuple of (anonymized_text, entity_mapping)
        
    Raises:
        ValueError: If message is empty or invalid
    """
```

### Naming Conventions
- **Files**: lowercase with underscores (`state_manager.py`)
- **Classes**: PascalCase (`PIIAnonymizer`, `RedisStateManager`)
- **Functions/Methods**: snake_case (`get_anonymizer`, `process_message`)
- **Constants**: UPPER_SNAKE_CASE (`DEFAULT_TTL`, `MAX_RETRIES`)
- **Private members**: prefix with underscore (`_internal_method`)

### Import Organization
1. Standard library imports
2. Third-party imports
3. Local application imports

```python
import logging
from typing import Optional, Dict

from fastapi import FastAPI, Depends
from pydantic import BaseModel

from config import get_settings
from models import ChatRequest
```

## Architecture Patterns

### Dependency Injection
Use FastAPI's `Depends()` for injecting services:
```python
@app.post("/anonymize")
async def anonymize(
    request: AnonymizeRequest,
    settings: Settings = Depends(get_settings),
    anonymizer: PIIAnonymizer = Depends(get_anonymizer),
    state_manager = Depends(get_state_manager_dep)
):
```

### Error Handling
- Use `HTTPException` for API errors
- Create custom exception classes for domain-specific errors
- Always include meaningful error messages
- Log errors with appropriate severity

```python
try:
    result = await process_data(data)
except ValidationError as e:
    logger.warning(f"Validation failed: {e}")
    raise HTTPException(status_code=400, detail=str(e))
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)
    raise HTTPException(status_code=500, detail="Internal server error")
```

### Async Context Managers
Use for resource lifecycle management:
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    logger.info("Starting application...")
    yield
    logger.info("Shutting down application...")
```

## Testing Guidelines

### Test File Location
- All tests in `tests/` directory
- Test files named `test_*.py`
- Use pytest fixtures for shared resources

### Test Structure
```python
@pytest.fixture
def anonymizer():
    """Create a PIIAnonymizer instance for testing."""
    return PIIAnonymizer()

class TestAnonymization:
    """Test suite for anonymization functionality."""
    
    def test_anonymize_person_name(self, anonymizer):
        """Test that person names are properly anonymized."""
        text = "John Smith called yesterday"
        result = anonymizer.anonymize(text)
        
        assert "John" not in result.anonymized_text
        assert "[PERSON_1]" in result.anonymized_text
```

### Running Tests
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test file
pytest tests/test_gateway.py -v

# Run specific test class
pytest tests/test_gateway.py::TestAnonymization -v
```

## PII Detection Categories

### Standard PII Types (Presidio)
- `PERSON` - Personal names
- `EMAIL_ADDRESS` - Email addresses
- `PHONE_NUMBER` - Phone numbers
- `CREDIT_CARD` - Credit card numbers
- `US_SSN` - US Social Security Numbers
- `DATE_TIME` - Dates and times
- `LOCATION` - Geographic locations
- `IP_ADDRESS` - IP addresses

### Indian PII Types (Custom Recognizers)
- `IN_PAN` - Indian PAN card numbers
- `IN_AADHAAR` - Aadhaar numbers (12 digits with Verhoeff)
- `IN_IFSC` - Bank IFSC codes
- `IN_VEHICLE_REGISTRATION` - Vehicle registration numbers
- `IN_VOTER` - Voter ID numbers
- `IN_GST` - GST numbers
- `IN_DRIVING_LICENSE` - Driving license numbers

## API Endpoints

### Core Endpoints
- `POST /anonymize` - Anonymize text, returns session_id
- `POST /deanonymize` - Restore PII using session_id
- `POST /chat` - Proxy to LLM with automatic PII protection

### Health & Monitoring
- `GET /health` - Health check endpoint
- `GET /docs` - OpenAPI documentation

## Security Considerations

When working with this codebase:
1. **Never log PII** - Use placeholders or redact sensitive data
2. **Validate all inputs** - Use Pydantic models for validation
3. **Sanitize outputs** - Prevent injection attacks
4. **Use environment variables** - Never hardcode secrets
5. **Rate limiting** - Use SlowAPI middleware for protection

## Common Tasks

### Adding a New PII Recognizer
1. Create a recognizer class in `recognizers.py`
2. Register it in `anonymizer_engine.py`
3. Add tests in `tests/test_gateway.py`

### Adding a New API Endpoint
1. Define Pydantic models in `models.py`
2. Add the endpoint in `main.py`
3. Add tests for the endpoint
4. Update OpenAPI documentation

### Modifying Configuration
1. Add new settings to `config.py`
2. Update `.env.example` with defaults
3. Document in README.md

## Build and Run Commands

```bash
# Development
python main.py
uvicorn main:app --reload --port 8000

# Testing
pytest tests/ -v --tb=short

# Docker
docker-compose up --build
docker-compose --profile debug up  # With Redis Commander

# Dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

## Key Files Reference

| File | Purpose |
|------|---------|
| `main.py` | FastAPI app, routes, lifespan management |
| `anonymizer_engine.py` | PII detection with Presidio |
| `recognizers.py` | Custom Indian PII patterns |
| `state_manager.py` | Session/mapping persistence |
| `models.py` | Request/response schemas |
| `config.py` | Environment configuration |
| `middleware.py` | Rate limiting, logging |
| `security.py` | Input validation, filters |

## Do's and Don'ts

### ✅ Do
- Use async/await for I/O operations
- Write comprehensive docstrings
- Add type hints to all functions
- Create unit tests for new features
- Use dependency injection
- Handle errors gracefully

### ❌ Don't
- Log actual PII data
- Hardcode configuration values
- Skip input validation
- Use blocking I/O in async functions
- Ignore test failures
- Commit secrets to version control
