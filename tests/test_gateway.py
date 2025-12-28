"""
Unit tests for PII Anonymization Gateway.
Run with: pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient

# Import after setting test env
import os
os.environ["OPENAI_API_KEY"] = ""  # Force mock client

from main import app, get_state_manager_dep
from anonymizer_engine import PIIAnonymizer, anonymize_and_map, de_anonymize
from recognizers import (
    IndianPANRecognizer,
    IndianAadhaarRecognizer,
    IndianPhoneRecognizer,
)
from state_manager import InMemoryStateManager


# === Shared Test State ===

# Shared state manager for all API tests
_shared_state_manager = InMemoryStateManager()


# === Fixtures ===

@pytest.fixture(scope="session")
def shared_state_manager():
    """Shared state manager for all tests."""
    return _shared_state_manager


@pytest.fixture
def client(shared_state_manager):
    """Test client for API testing with shared state manager."""
    # Override the state manager dependency
    def override_get_state_manager_dep():
        return shared_state_manager
    
    app.dependency_overrides[get_state_manager_dep] = override_get_state_manager_dep
    
    test_client = TestClient(app)
    
    yield test_client
    
    # Clean up overrides
    app.dependency_overrides = {}


@pytest.fixture
def anonymizer():
    """Fresh anonymizer instance."""
    return PIIAnonymizer(use_indian_recognizers=True)


@pytest.fixture
def state_manager():
    """In-memory state manager for testing."""
    return InMemoryStateManager()


# === Anonymizer Tests ===

class TestAnonymizer:
    """Tests for core anonymization logic."""
    
    def test_detect_person_name(self, anonymizer):
        """Should detect person names."""
        result = anonymizer.anonymize("Hello, I am Rohan Kumar.")
        
        assert "[PERSON_" in result.anonymized_text
        assert "Rohan" not in result.anonymized_text or "Kumar" not in result.anonymized_text
    
    def test_detect_phone_number(self, anonymizer):
        """Should detect phone numbers."""
        result = anonymizer.anonymize("Call me at 9876543210")
        
        assert "9876543210" not in result.anonymized_text
        assert "[" in result.anonymized_text  # Has placeholder
    
    def test_detect_email(self, anonymizer):
        """Should detect email addresses."""
        result = anonymizer.anonymize("Email: test@example.com")
        
        assert "test@example.com" not in result.anonymized_text
        assert "[EMAIL_ADDRESS_" in result.anonymized_text
    
    def test_multiple_entities(self, anonymizer):
        """Should detect multiple entity types."""
        text = "I am Rohan, email: rohan@test.com, phone: 9876543210"
        result = anonymizer.anonymize(text)
        
        assert len(result.entities_found) >= 2
        assert "rohan@test.com" not in result.anonymized_text
    
    def test_de_anonymize(self, anonymizer):
        """Should restore original values."""
        original = "Hello, I am Rohan."
        result = anonymizer.anonymize(original)
        
        # Simulate LLM response using placeholders
        llm_response = f"Nice to meet you, {result.anonymized_text}"
        restored = anonymizer.de_anonymize(llm_response, result.mapping)
        
        assert "Rohan" in restored
    
    def test_empty_text(self, anonymizer):
        """Should handle empty text."""
        result = anonymizer.anonymize("")
        
        assert result.anonymized_text == ""
        assert result.mapping == {}
    
    def test_no_pii(self, anonymizer):
        """Should return unchanged text when no PII."""
        text = "Hello world, this is a test message."
        result = anonymizer.anonymize(text)
        
        assert result.anonymized_text == text
    
    def test_overlap_resolution(self, anonymizer):
        """Should handle overlapping entity detections."""
        # "John Smith" might be detected as both a full name and first name
        result = anonymizer.anonymize("Contact John Smith at john.smith@email.com")
        
        # Should have resolved overlaps properly
        assert "John Smith" not in result.anonymized_text
        assert "john.smith@email.com" not in result.anonymized_text


# === Indian Recognizer Tests ===

class TestIndianRecognizers:
    """Tests for Indian PII recognizers."""
    
    def test_pan_card_valid(self, anonymizer):
        """Should detect valid PAN card numbers."""
        result = anonymizer.anonymize("My PAN is ABCDE1234F")
        
        assert "ABCDE1234F" not in result.anonymized_text
        assert "[IN_PAN_" in result.anonymized_text
    
    def test_aadhaar_spaced(self, anonymizer):
        """Should detect Aadhaar with spaces."""
        result = anonymizer.anonymize("Aadhaar: 2345 6789 0123")
        
        assert "2345 6789 0123" not in result.anonymized_text
        assert "[IN_AADHAAR_" in result.anonymized_text
    
    def test_aadhaar_dashed(self, anonymizer):
        """Should detect Aadhaar with dashes."""
        result = anonymizer.anonymize("Aadhaar: 2345-6789-0123")
        
        assert "2345-6789-0123" not in result.anonymized_text
        assert "[IN_AADHAAR_" in result.anonymized_text
    
    def test_indian_phone_with_country_code(self, anonymizer):
        """Should detect Indian phone with +91."""
        result = anonymizer.anonymize("Call +919876543210")
        
        # Should detect as phone number
        assert "9876543210" not in result.anonymized_text
    
    def test_ifsc_code(self, anonymizer):
        """Should detect IFSC codes."""
        result = anonymizer.anonymize("IFSC: SBIN0001234")
        
        assert "SBIN0001234" not in result.anonymized_text
        assert "[IN_IFSC_" in result.anonymized_text
    
    def test_gst_number(self, anonymizer):
        """Should detect GST numbers."""
        result = anonymizer.anonymize("GST: 29ABCDE1234F1Z5")
        
        assert "29ABCDE1234F1Z5" not in result.anonymized_text
        assert "[IN_GST_" in result.anonymized_text
    
    def test_indian_phone_not_uk_nhs(self, anonymizer):
        """Should NOT detect Indian phone as UK_NHS."""
        result = anonymizer.anonymize("Call me at 9876543210")
        
        # Should be detected as Indian phone, not UK_NHS
        entity_types = [e["type"] for e in result.entities_found]
        assert "UK_NHS" not in entity_types
        # Should have IN_PHONE_NUMBER or PHONE_NUMBER
        assert any("PHONE" in t for t in entity_types)
    
    def test_entity_confidence_scores(self, anonymizer):
        """Should return valid confidence scores."""
        result = anonymizer.anonymize("My email is test@example.com")
        
        assert len(result.entities_found) > 0
        for entity in result.entities_found:
            assert "confidence" in entity
            assert 0.0 <= entity["confidence"] <= 1.0


# === State Manager Tests ===

class TestStateManager:
    """Tests for state management."""
    
    def test_store_and_retrieve(self, state_manager):
        """Should store and retrieve mappings."""
        request_id = state_manager.generate_request_id()
        mapping = {"[PERSON_1]": "John"}
        
        state_manager.store_mapping(request_id, mapping)
        retrieved = state_manager.retrieve_mapping(request_id)
        
        assert retrieved == mapping
    
    def test_retrieve_nonexistent(self, state_manager):
        """Should return None for non-existent mapping."""
        result = state_manager.retrieve_mapping("nonexistent-id")
        assert result is None
    
    def test_delete_mapping(self, state_manager):
        """Should delete mappings."""
        request_id = state_manager.generate_request_id()
        mapping = {"[PERSON_1]": "John"}
        
        state_manager.store_mapping(request_id, mapping)
        deleted = state_manager.delete_mapping(request_id)
        
        assert deleted is True
        assert state_manager.retrieve_mapping(request_id) is None
    
    def test_unique_request_ids(self, state_manager):
        """Should generate unique request IDs."""
        ids = [state_manager.generate_request_id() for _ in range(100)]
        assert len(set(ids)) == 100


# === API Tests ===

class TestAPI:
    """Tests for FastAPI endpoints."""
    
    def test_health_endpoint(self, client):
        """Should return health status."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
    
    def test_root_endpoint(self, client):
        """Should return service info."""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "version" in data
    
    def test_entities_endpoint(self, client):
        """Should list supported entities."""
        response = client.get("/entities")
        
        assert response.status_code == 200
        data = response.json()
        assert "entities" in data
        assert len(data["entities"]) > 0
    
    def test_anonymize_endpoint(self, client):
        """Should anonymize text."""
        response = client.post(
            "/anonymize",
            json={"text": "My name is Rohan, phone: 9876543210"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "request_id" in data
        assert "anonymized_text" in data
        assert "Rohan" not in data["anonymized_text"]
    
    def test_deanonymize_endpoint(self, client):
        """Should de-anonymize text."""
        # First anonymize
        anon_response = client.post(
            "/anonymize",
            json={"text": "Hello Rohan"}
        )
        request_id = anon_response.json()["request_id"]
        anon_text = anon_response.json()["anonymized_text"]
        
        # Then de-anonymize
        deanon_response = client.post(
            "/deanonymize",
            json={"request_id": request_id, "text": anon_text}
        )
        
        assert deanon_response.status_code == 200
        assert "Rohan" in deanon_response.json()["original_text"]
    
    def test_deanonymize_invalid_request_id(self, client):
        """Should return 404 for invalid request ID."""
        response = client.post(
            "/deanonymize",
            json={"request_id": "invalid-id", "text": "test"}
        )
        
        assert response.status_code == 404
    
    def test_chat_endpoint_mock(self, client):
        """Should handle chat with mock LLM."""
        response = client.post(
            "/chat",
            json={"message": "Hi, I am Rohan from Mumbai"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "request_id" in data
        assert "final_response" in data
    
    def test_delete_mapping_endpoint(self, client):
        """Should delete mapping."""
        # Create mapping
        anon_response = client.post(
            "/anonymize",
            json={"text": "Test user"}
        )
        request_id = anon_response.json()["request_id"]
        
        # Delete it
        delete_response = client.delete(f"/mapping/{request_id}")
        
        assert delete_response.status_code == 200


# === Legacy Function Tests ===

class TestLegacyFunctions:
    """Tests for backward-compatible functions."""
    
    def test_anonymize_and_map(self, anonymizer):
        """Should work with legacy function."""
        anon_text, mapping = anonymize_and_map("Hello John")
        
        assert "John" not in anon_text
        assert len(mapping) > 0
    
    def test_de_anonymize_legacy(self, anonymizer):
        """Should work with legacy de_anonymize."""
        anon_text, mapping = anonymize_and_map("Hello John")
        restored = de_anonymize(anon_text, mapping)
        
        assert "John" in restored
