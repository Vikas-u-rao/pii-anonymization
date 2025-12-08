"""
Logging configuration for PII Gateway.
Structured logging for production observability.
"""

import logging
import sys
import json
from datetime import datetime
from typing import Any, Dict
from config import get_settings


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    Compatible with ELK, CloudWatch, Datadog, etc.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "request_id"):
            log_data["request_id"] = record.request_id
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "entities_count"):
            log_data["entities_count"] = record.entities_count
        
        return json.dumps(log_data)


class PIIAuditLogger:
    """
    Specialized audit logger for PII operations.
    Logs anonymization events WITHOUT logging actual PII.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("pii_audit")
        self.logger.setLevel(logging.INFO)
    
    def log_anonymization(
        self,
        request_id: str,
        entity_types: list,
        entity_count: int,
        text_length: int,
        source_ip: str = None
    ):
        """Log an anonymization event without PII."""
        self.logger.info(
            "Anonymization completed",
            extra={
                "request_id": request_id,
                "entity_types": entity_types,
                "entities_count": entity_count,
                "text_length": text_length,
                "source_ip": source_ip,
                "event_type": "anonymization"
            }
        )
    
    def log_deanonymization(
        self,
        request_id: str,
        success: bool,
        source_ip: str = None
    ):
        """Log a de-anonymization event."""
        self.logger.info(
            "De-anonymization requested",
            extra={
                "request_id": request_id,
                "success": success,
                "source_ip": source_ip,
                "event_type": "deanonymization"
            }
        )
    
    def log_mapping_expired(self, request_id: str):
        """Log when a mapping was not found (likely expired)."""
        self.logger.warning(
            "Mapping not found or expired",
            extra={
                "request_id": request_id,
                "event_type": "mapping_expired"
            }
        )


def setup_logging():
    """
    Configure logging for the application.
    Uses JSON format in production, human-readable in debug.
    """
    settings = get_settings()
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if settings.debug else logging.INFO)
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    
    if settings.debug:
        # Human-readable format for development
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        # JSON format for production
        formatter = JSONFormatter()
    
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    return root_logger


# Singleton audit logger
_audit_logger = None

def get_audit_logger() -> PIIAuditLogger:
    """Get or create audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = PIIAuditLogger()
    return _audit_logger
