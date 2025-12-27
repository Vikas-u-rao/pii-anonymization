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


# Common brand names and words that should NOT be detected as person names
PERSON_DENY_LIST = {
    # Social Media & Tech Companies
    "linkedin", "facebook", "twitter", "instagram", "youtube", "tiktok", "snapchat",
    "whatsapp", "telegram", "discord", "reddit", "pinterest", "tumblr", "medium",
    "google", "microsoft", "apple", "amazon", "netflix", "spotify", "uber", "lyft",
    "airbnb", "dropbox", "slack", "zoom", "skype", "teams", "outlook", "gmail",
    "yahoo", "bing", "duckduckgo", "brave", "firefox", "chrome", "safari", "edge",
    "paypal", "stripe", "razorpay", "paytm", "phonepe", "gpay", "venmo", "cashapp",
    
    # AI/ML & Developer Tools
    "chatgpt", "openai", "gemini", "claude", "copilot", "alexa", "siri", "cortana",
    "github", "gitlab", "bitbucket", "jira", "confluence", "notion", "figma", "canva",
    "docker", "kubernetes", "terraform", "ansible", "jenkins", "travis", "circleci",
    "mongodb", "postgres", "mysql", "redis", "elasticsearch", "kafka", "rabbitmq",
    "aws", "azure", "gcp", "heroku", "vercel", "netlify", "digitalocean", "cloudflare",
    "pytorch", "tensorflow", "keras", "scikit", "pandas", "numpy", "jupyter",
    
    # Professional Platforms & Services
    "glassdoor", "indeed", "naukri", "monster", "angel", "wellfound", "upwork", "fiverr",
    "coursera", "udemy", "edx", "udacity", "pluralsight", "skillshare", "codecademy",
    "leetcode", "hackerrank", "codechef", "codeforces", "topcoder", "kaggle",
    "stackoverflow", "quora", "wikipedia", "arxiv", "researchgate",
    
    # Days and Months
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december",
    
    # Countries and Regions
    "india", "usa", "america", "europe", "asia", "africa", "australia", "canada",
    "england", "britain", "china", "japan", "germany", "france", "italy", "spain",
    "brazil", "mexico", "russia", "korea", "singapore", "dubai", "london", "paris",
    "tokyo", "beijing", "sydney", "toronto", "berlin", "mumbai", "delhi", "bangalore",
    "hyderabad", "chennai", "kolkata", "pune", "ahmedabad", "jaipur", "lucknow",
    
    # Job Titles and Roles
    "ceo", "cto", "cfo", "coo", "cmo", "cio", "vp", "svp", "evp", "avp",
    "director", "manager", "lead", "senior", "junior", "intern", "associate",
    "engineer", "developer", "analyst", "consultant", "architect", "designer",
    "founder", "cofounder", "partner", "president", "chairman", "head",
    
    # Common Words & Titles
    "hello", "hi", "hey", "dear", "thanks", "thank", "regards", "sincerely",
    "mr", "mrs", "ms", "dr", "prof", "sir", "madam", "miss",
    "software", "hardware", "data", "cloud", "mobile", "web", "frontend", "backend",
    "fullstack", "devops", "machine", "learning", "artificial", "intelligence",
    "resume", "portfolio", "profile", "bio", "summary", "experience", "skills",
    
    # Indian Companies & Brands
    "infosys", "wipro", "tcs", "hcl", "cognizant", "accenture", "deloitte", "kpmg",
    "flipkart", "swiggy", "zomato", "ola", "byju", "unacademy", "zerodha", "cred",
    "reliance", "tata", "mahindra", "bajaj", "hdfc", "icici", "axis", "kotak", "sbi",
    
    # Education
    "iit", "iim", "nit", "bits", "vit", "mit", "stanford", "harvard", "oxford",
    "cambridge", "berkeley", "cmu", "caltech", "princeton", "yale", "cornell",
    "university", "college", "institute", "school", "academy",
}


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
        
        # Use Presidio's built-in allow_list for exact matches
        # Convert deny list to allow list format for common words
        allow_list = list(PERSON_DENY_LIST)
        
        results = self.analyzer.analyze(
            text=text,
            language=lang,
            entities=entities,
            score_threshold=self.score_threshold,
            allow_list=allow_list  # Presidio's native filtering
        )
        
        # Additional filtering for case-insensitive matches not caught by allow_list
        filtered_results = []
        for result in results:
            if result.entity_type == "PERSON":
                detected_text = text[result.start:result.end].lower().strip()
                if detected_text in PERSON_DENY_LIST:
                    logger.debug(f"Filtered false positive PERSON: {detected_text}")
                    continue
            filtered_results.append(result)
        
        return self._resolve_overlaps(filtered_results)
    
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
