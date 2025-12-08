"""
Production-ready PII Anonymization Engine.
Core logic for detecting, anonymizing, and de-anonymizing PII.
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
import logging

from config import get_settings
from recognizers import get_indian_recognizers

logger = logging.getLogger(__name__)


@dataclass
class AnonymizationResult:
    """Result container for anonymization operation."""
    anonymized_text: str
    mapping: Dict[str, str]
    entities_found: List[Dict]
    original_text: str


class PIIAnonymizer:
    """
    Production PII Anonymization Engine.
    
    Features:
    - Built-in Presidio recognizers (PERSON, EMAIL, PHONE, SSN, etc.)
    - Custom Indian recognizers (PAN, Aadhaar, etc.)
    - Overlap conflict resolution (highest confidence wins)
    - Indexed placeholder generation for LLM context preservation
    - Reversible anonymization with mapping
    """
    
    def __init__(self, use_indian_recognizers: bool = True):
        """
        Initialize the anonymization engine.
        
        Args:
            use_indian_recognizers: Whether to include Indian PII recognizers
        """
        settings = get_settings()
        self.language = settings.presidio_language
        self.score_threshold = settings.presidio_score_threshold
        
        # Initialize Presidio Analyzer
        self.analyzer = AnalyzerEngine()
        
        # Add custom Indian recognizers
        if use_indian_recognizers:
            self._register_indian_recognizers()
        
        logger.info(f"PIIAnonymizer initialized with {len(self.analyzer.registry.recognizers)} recognizers")
    
    def _register_indian_recognizers(self):
        """Register custom Indian PII recognizers."""
        indian_recognizers = get_indian_recognizers()
        
        for recognizer in indian_recognizers:
            self.analyzer.registry.add_recognizer(recognizer)
            logger.debug(f"Registered recognizer: {recognizer.supported_entities}")
    
    def _resolve_overlaps(
        self, 
        results: List[RecognizerResult]
    ) -> List[RecognizerResult]:
        """
        Resolve overlapping entity detections.
        
        Strategy:
        1. Sort by confidence score (highest first)
        2. For ties, prefer longer matches
        3. Mark non-overlapping entities
        
        Args:
            results: Raw Presidio results
            
        Returns:
            List of non-overlapping results
        """
        if not results:
            return []
        
        # Sort by score (desc), then by length (desc) for ties
        sorted_results = sorted(
            results,
            key=lambda x: (x.score, x.end - x.start),
            reverse=True
        )
        
        unique_results = []
        occupied_ranges: List[Tuple[int, int]] = []
        
        for result in sorted_results:
            is_overlapping = False
            
            for start, end in occupied_ranges:
                # Check for overlap
                if max(start, result.start) < min(end, result.end):
                    is_overlapping = True
                    break
            
            if not is_overlapping:
                unique_results.append(result)
                occupied_ranges.append((result.start, result.end))
        
        return unique_results
    
    def analyze(
        self, 
        text: str,
        entities: Optional[List[str]] = None,
        language: Optional[str] = None
    ) -> List[RecognizerResult]:
        """
        Analyze text for PII entities.
        
        Args:
            text: Input text to analyze
            entities: Optional list of entity types to detect
            language: Language code (default from settings)
            
        Returns:
            List of detected entities
        """
        lang = language or self.language
        
        results = self.analyzer.analyze(
            text=text,
            language=lang,
            entities=entities,
            score_threshold=self.score_threshold
        )
        
        return self._resolve_overlaps(results)
    
    def anonymize(self, text: str) -> AnonymizationResult:
        """
        Anonymize PII in text with indexed placeholders.
        
        Args:
            text: Input text containing PII
            
        Returns:
            AnonymizationResult with anonymized text and mapping
        """
        # Analyze for PII
        results = self.analyze(text)
        
        # Sort by position (reverse) for safe string replacement
        results.sort(key=lambda x: x.start, reverse=True)
        
        mapping: Dict[str, str] = {}
        entities_found: List[Dict] = []
        entity_counters: Dict[str, int] = {}
        anonymized_text = text
        
        for result in results:
            original_value = text[result.start:result.end]
            entity_type = result.entity_type
            
            # Increment counter for this entity type
            entity_counters[entity_type] = entity_counters.get(entity_type, 0) + 1
            count = entity_counters[entity_type]
            
            # Generate indexed placeholder
            placeholder = f"[{entity_type}_{count}]"
            
            # Store mapping (placeholder -> original)
            mapping[placeholder] = original_value
            
            # Record entity info
            entities_found.append({
                "type": entity_type,
                "original": original_value,
                "placeholder": placeholder,
                "confidence": result.score,
                "start": result.start,
                "end": result.end
            })
            
            # Replace in text
            anonymized_text = (
                anonymized_text[:result.start] +
                placeholder +
                anonymized_text[result.end:]
            )
        
        logger.info(f"Anonymized {len(results)} entities")
        
        return AnonymizationResult(
            anonymized_text=anonymized_text,
            mapping=mapping,
            entities_found=entities_found,
            original_text=text
        )
    
    def de_anonymize(self, text: str, mapping: Dict[str, str]) -> str:
        """
        Restore original PII values from placeholders.
        
        Args:
            text: Text containing placeholders
            mapping: Dictionary of {placeholder: original_value}
            
        Returns:
            Text with placeholders replaced by original values
        """
        result = text
        
        for placeholder, original_value in mapping.items():
            result = result.replace(placeholder, original_value)
        
        return result
    
    def get_supported_entities(self) -> List[str]:
        """Get list of all supported entity types."""
        return self.analyzer.get_supported_entities(language=self.language)


# Singleton instance for reuse
_anonymizer_instance: Optional[PIIAnonymizer] = None


def get_anonymizer() -> PIIAnonymizer:
    """
    Get or create singleton PIIAnonymizer instance.
    
    Returns:
        Configured PIIAnonymizer instance
    """
    global _anonymizer_instance
    
    if _anonymizer_instance is None:
        _anonymizer_instance = PIIAnonymizer()
    
    return _anonymizer_instance


# === Backward Compatibility Functions ===

def anonymize_and_map(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Legacy function for backward compatibility.
    
    Args:
        text: Input text
        
    Returns:
        Tuple of (anonymized_text, mapping)
    """
    anonymizer = get_anonymizer()
    result = anonymizer.anonymize(text)
    return result.anonymized_text, result.mapping


def de_anonymize(text: str, mapping: Dict[str, str]) -> str:
    """
    Legacy function for backward compatibility.
    
    Args:
        text: Text with placeholders
        mapping: Placeholder to original value mapping
        
    Returns:
        De-anonymized text
    """
    anonymizer = get_anonymizer()
    return anonymizer.de_anonymize(text, mapping)


# === CLI Demo ===

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Test cases
    test_cases = [
        "Hello, I am Rohan. My phone number is 9876543210.",
        "My PAN card is ABCDE1234F and Aadhaar is 2345 6789 0123.",
        "Contact me at rohan@example.com or +91-9876543210.",
        "Send payment to account 12345678901234 IFSC: HDFC0001234",
        "My passport number is A1234567 and voter ID is ABC1234567",
    ]
    
    anonymizer = PIIAnonymizer()
    
    print("=" * 60)
    print("PII Anonymization Engine - Demo")
    print("=" * 60)
    
    for i, text in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        print(f"Original:   {text}")
        
        result = anonymizer.anonymize(text)
        
        print(f"Anonymized: {result.anonymized_text}")
        print(f"Mapping:    {result.mapping}")
        print(f"Entities:   {[e['type'] for e in result.entities_found]}")
        
        # Simulate LLM response
        simulated_response = f"I received your message about {result.anonymized_text}"
        restored = anonymizer.de_anonymize(simulated_response, result.mapping)
        print(f"Restored:   {restored}")
