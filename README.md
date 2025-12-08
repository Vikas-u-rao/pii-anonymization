# PII Anonymization Gateway

A production-ready middleware service that sits between users and LLMs (like OpenAI/Claude) to protect sensitive Personal Identifiable Information (PII).

## Features

- **PII Detection**: Automatically detects names, phone numbers, emails, SSNs, credit cards, and more
- **Indian PII Support**: Custom recognizers for PAN, Aadhaar, IFSC, GST, Voter ID, Driving License
- **Reversible Anonymization**: Replaces PII with indexed placeholders (`[PERSON_1]`, `[IN_PAN_1]`)
- **LLM Integration**: Proxies requests to OpenAI with automatic PII protection
- **Redis State Management**: Distributed mapping storage with TTL for horizontal scaling
- **REST API**: Clean FastAPI endpoints with OpenAPI documentation

## Architecture

```
User → [Original Message] → Gateway → [Anonymized Message] → LLM
                                ↓
                          Redis (mapping)
                                ↓
User ← [Restored Response] ← Gateway ← [Raw Response] ← LLM
```

## Project Structure

```
hipaa-bypass/
├── main.py              # FastAPI application entry point
├── config.py            # Configuration management (Pydantic Settings)
├── models.py            # Pydantic models for API validation
├── anonymizer_engine.py # Core PII detection and anonymization logic
├── recognizers.py       # Custom Indian PII recognizers
├── state_manager.py     # Redis-based state management
├── llm_client.py        # OpenAI client abstraction
├── requirements.txt     # Python dependencies
├── Dockerfile           # Multi-stage production Dockerfile
├── docker-compose.yml   # Docker Compose with Redis
├── .env.example         # Environment variables template
└── .gitignore           # Git ignore rules
```

## Quick Start

### Option 1: Local Development

1. **Clone and setup:**
   ```bash
   cd hipaa-bypass
   python -m venv venv
   .\venv\Scripts\Activate.ps1  # Windows
   # source venv/bin/activate   # Linux/Mac
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_lg
   ```

3. **Configure environment:**
   ```bash
   copy .env.example .env
   # Edit .env with your OpenAI API key
   ```

4. **Start Redis (optional, falls back to in-memory):**
   ```bash
   docker run -d -p 6379:6379 redis:7-alpine
   ```

5. **Run the server:**
   ```bash
   python main.py
   # Or: uvicorn main:app --reload
   ```

6. **Access the API:**
   - API: http://localhost:8000
   - Docs: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

### Option 2: Docker Compose (Recommended)

1. **Configure environment:**
   ```bash
   copy .env.example .env
   # Edit .env with your OpenAI API key
   ```

2. **Build and run:**
   ```bash
   docker-compose up --build
   ```

3. **With Redis Admin UI (debug mode):**
   ```bash
   docker-compose --profile debug up
   # Redis Commander: http://localhost:8081
   ```

## API Endpoints

### Chat with PII Protection
```bash
POST /chat
{
  "message": "Hello, I am Rohan. My phone is 9876543210.",
  "system_prompt": "You are a helpful assistant."
}
```

Response:
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "original_message": "Hello, I am Rohan. My phone is 9876543210.",
  "anonymized_message": "Hello, I am [PERSON_1]. My phone is [PHONE_NUMBER_1].",
  "llm_response": "Hello [PERSON_1], I've noted your phone [PHONE_NUMBER_1].",
  "final_response": "Hello Rohan, I've noted your phone 9876543210.",
  "entities_detected": [...]
}
```

### Anonymize Only
```bash
POST /anonymize
{
  "text": "My PAN is ABCDE1234F and Aadhaar is 2345 6789 0123."
}
```

### De-anonymize
```bash
POST /deanonymize
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "text": "Your [IN_PAN_1] is verified."
}
```

### Health Check
```bash
GET /health
```

### List Supported Entities
```bash
GET /entities
```

## Supported Indian PII Types

| Entity Type | Example | Pattern |
|-------------|---------|---------|
| `IN_PAN` | ABCDE1234F | 5 letters + 4 digits + 1 letter |
| `IN_AADHAAR` | 2345 6789 0123 | 12 digits (spaces/dashes optional) |
| `IN_PHONE_NUMBER` | +91-9876543210 | Indian mobile format |
| `IN_VOTER_ID` | ABC1234567 | 3 letters + 7 digits |
| `IN_PASSPORT` | A1234567 | 1 letter + 7 digits |
| `IN_DRIVING_LICENSE` | MH01 2020 0001234 | State + RTO + Year + Number |
| `IN_GST` | 27ABCDE1234F1Z5 | State + PAN + Entity + Checksum |
| `IN_IFSC` | HDFC0001234 | 4 letters + 0 + 6 alphanumeric |
| `IN_BANK_ACCOUNT` | 12345678901234 | 11-16 digits (context-dependent) |

## Configuration

All settings via environment variables:

```env
# OpenAI
OPENAI_API_KEY=sk-your-key
OPENAI_MODEL=gpt-3.5-turbo
OPENAI_MAX_TOKENS=1000

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_TTL_SECONDS=3600

# Presidio
PRESIDIO_SCORE_THRESHOLD=0.5
```

## Security Considerations

1. **Never log PII**: The mapping is stored in Redis, not logs
2. **TTL-based cleanup**: Mappings auto-expire (default 1 hour)
3. **Non-root container**: Docker runs as unprivileged user
4. **CORS configuration**: Restrict origins in production
5. **API key protection**: Use secrets management in production

## Testing

```bash
# Test anonymization
curl -X POST http://localhost:8000/anonymize \
  -H "Content-Type: application/json" \
  -d '{"text": "My name is Rohan, PAN: ABCDE1234F"}'

# Test chat
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "I am Rohan from Mumbai, phone: 9876543210"}'
```

## Monitoring

- Health endpoint: `/health`
- Redis stats included in health response
- Container health checks configured
- Structured logging for observability

## Development

```bash
# Run with hot reload
uvicorn main:app --reload --log-level debug

# Run anonymizer demo
python anonymizer_engine.py
```

## License

MIT License - Use responsibly for legitimate privacy protection.
