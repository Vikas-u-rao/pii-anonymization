"""
Security utilities for PII Gateway.
Input validation, sanitization, and prompt injection detection.
"""

import re
from typing import Tuple, List
import logging

logger = logging.getLogger(__name__)


class PromptInjectionDetector:
    """
    Detects potential prompt injection attacks.
    Prevents malicious users from manipulating LLM behavior.
    """
    
    # Common prompt injection patterns
    INJECTION_PATTERNS = [
        # Direct instruction override
        r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?)",
        r"disregard\s+(all\s+)?(previous|above|prior)",
        r"forget\s+(everything|all|what)\s+(you|I)\s+(told|said)",
        
        # Role manipulation
        r"you\s+are\s+now\s+(a|an|the)\s+\w+",
        r"pretend\s+(to\s+be|you\s+are)",
        r"act\s+as\s+(a|an|if)",
        r"roleplay\s+as",
        
        # System prompt extraction
        r"(what|show|reveal|tell)\s+(is|me|are)\s+(your|the)\s+(system\s+)?(prompt|instructions?)",
        r"repeat\s+(your|the)\s+(system\s+)?(prompt|instructions?)",
        r"print\s+(your|the)\s+instructions?",
        
        # Delimiter attacks
        r"```\s*(system|admin|root)",
        r"\[\[.*?(system|admin|override).*?\]\]",
        r"<\s*(system|admin|override)",
        
        # Jailbreak attempts
        r"DAN\s*mode",
        r"developer\s+mode\s+(enabled|on|activate)",
        r"bypass\s+(filters?|restrictions?|safety)",
    ]
    
    def __init__(self):
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.INJECTION_PATTERNS
        ]
    
    def detect(self, text: str) -> Tuple[bool, List[str]]:
        """
        Check text for prompt injection patterns.
        
        Args:
            text: Input text to check
            
        Returns:
            Tuple of (is_suspicious, matched_patterns)
        """
        matched = []
        
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(text):
                matched.append(self.INJECTION_PATTERNS[i])
        
        is_suspicious = len(matched) > 0
        
        if is_suspicious:
            logger.warning(
                f"Potential prompt injection detected: {len(matched)} patterns matched"
            )
        
        return is_suspicious, matched
    
    def sanitize(self, text: str) -> str:
        """
        Sanitize text by escaping potential injection vectors.
        
        Args:
            text: Input text
            
        Returns:
            Sanitized text
        """
        # Escape common delimiters used in attacks
        sanitized = text
        
        # Escape triple backticks
        sanitized = sanitized.replace("```", "'''")
        
        # Escape angle brackets (but preserve common HTML entities)
        sanitized = re.sub(r"<(?!/?[a-z]+>)", "&lt;", sanitized)
        sanitized = re.sub(r"(?<![a-z])>", "&gt;", sanitized)
        
        return sanitized


class InputValidator:
    """
    Validates and sanitizes user input.
    """
    
    # Max lengths
    MAX_MESSAGE_LENGTH = 10000
    MAX_SYSTEM_PROMPT_LENGTH = 2000
    
    # Allowed characters (Unicode-friendly)
    DANGEROUS_CHARS = [
        "\x00",  # Null byte
        "\x1b",  # Escape
    ]
    
    @classmethod
    def validate_message(cls, message: str) -> Tuple[bool, str]:
        """
        Validate user message.
        
        Args:
            message: User message
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not message:
            return False, "Message cannot be empty"
        
        if len(message) > cls.MAX_MESSAGE_LENGTH:
            return False, f"Message exceeds {cls.MAX_MESSAGE_LENGTH} characters"
        
        # Check for dangerous characters
        for char in cls.DANGEROUS_CHARS:
            if char in message:
                return False, "Message contains invalid characters"
        
        return True, ""
    
    @classmethod
    def sanitize_for_logging(cls, text: str, max_length: int = 100) -> str:
        """
        Sanitize text for safe logging (no PII should be logged).
        
        Args:
            text: Text to sanitize
            max_length: Maximum length to include
            
        Returns:
            Truncated, sanitized text
        """
        if len(text) > max_length:
            return text[:max_length] + "...[truncated]"
        return text


class ContentFilter:
    """
    Filter sensitive content categories.
    """
    
    # Add patterns for content you want to block entirely
    BLOCKED_PATTERNS = [
        # Example: Block requests for actual malware
        r"(create|write|generate)\s+(a\s+)?(malware|virus|trojan|ransomware)",
        r"(how\s+to\s+)?(hack|exploit|breach)\s+(into\s+)?",
    ]
    
    def __init__(self):
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.BLOCKED_PATTERNS
        ]
    
    def should_block(self, text: str) -> Tuple[bool, str]:
        """
        Check if content should be blocked.
        
        Args:
            text: Input text
            
        Returns:
            Tuple of (should_block, reason)
        """
        for pattern in self.compiled_patterns:
            if pattern.search(text):
                return True, "Content violates usage policy"
        
        return False, ""


# Singleton instances
_injection_detector = None
_content_filter = None


def get_injection_detector() -> PromptInjectionDetector:
    """Get or create injection detector."""
    global _injection_detector
    if _injection_detector is None:
        _injection_detector = PromptInjectionDetector()
    return _injection_detector


def get_content_filter() -> ContentFilter:
    """Get or create content filter."""
    global _content_filter
    if _content_filter is None:
        _content_filter = ContentFilter()
    return _content_filter
