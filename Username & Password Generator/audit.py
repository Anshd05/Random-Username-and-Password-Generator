#!/usr/bin/env python3
"""
Event-Driven Audit System
Logs security events WITHOUT storing sensitive data.
"""

import json
import logging
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Callable, List
from datetime import datetime


class AuditEventType(Enum):
    """Types of auditable security events"""
    CREDENTIAL_GENERATED = "credential_generated"
    CREDENTIAL_RETRIEVED = "credential_retrieved"
    RATE_LIMIT_HIT = "rate_limit_hit"
    CSRF_VIOLATION = "csrf_violation"
    DECRYPTION_FAILED = "decryption_failed"
    WEAK_PASSWORD_GENERATED = "weak_password_generated"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    BATCH_GENERATION = "batch_generation"
    ENCRYPTION_FAILED = "encryption_failed"
    VALIDATION_ERROR = "validation_error"


@dataclass
class AuditEvent:
    """Security audit event (no sensitive data stored)"""
    event_type: AuditEventType
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Anonymized identifiers only - no raw IPs or passwords
    client_fingerprint: str = ""
    session_hash: str = ""
    
    # Metrics only - no sensitive data
    entropy_bits: float = 0.0
    strength_level: str = ""
    strategy_used: str = ""
    password_length: int = 0
    
    # Security flags
    anomaly_detected: bool = False
    anomaly_reason: str = ""
    
    # Additional context
    error_message: str = ""
    request_path: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        d = asdict(self)
        d['event_type'] = self.event_type.value
        return d


class AuditLogger:
    """
    Security audit logger.
    Logs events WITHOUT sensitive data (no passwords, no raw IPs).
    Supports multiple handlers (file, SIEM, database).
    """
    
    def __init__(self):
        self._handlers: List[Callable] = []
        self._logger = logging.getLogger("CryptoGen.Audit")
        self._anomaly_detectors: List[Callable] = []
        
        # Configure logger
        if not self._logger.handlers:
            handler = logging.FileHandler('audit.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)
        
        # Add default file handler
        self.add_handler(self._file_handler)
    
    def add_handler(self, handler: Callable):
        """Add an event handler"""
        self._handlers.append(handler)
        return self  # Fluent interface
    
    def add_anomaly_detector(self, detector: Callable):
        """Add anomaly detection function"""
        self._anomaly_detectors.append(detector)
        return self
    
    def log(self, event: AuditEvent):
        """Log an audit event"""
        # Run anomaly detectors
        for detector in self._anomaly_detectors:
            try:
                anomaly = detector(event)
                if anomaly:
                    event.anomaly_detected = True
                    event.anomaly_reason = anomaly
                    break
            except Exception as e:
                self._logger.error(f"Anomaly detector error: {e}")
        
        # Dispatch to all handlers
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as e:
                self._logger.error(f"Audit handler error: {e}")
    
    def _file_handler(self, event: AuditEvent):
        """Write to audit log file"""
        log_entry = json.dumps(event.to_dict())
        self._logger.info(log_entry)
    
    # Anomaly detectors
    @staticmethod
    def detect_weak_password(event: AuditEvent) -> str | None:
        """Flag unusually weak passwords"""
        if event.entropy_bits < 40 and event.event_type == AuditEventType.CREDENTIAL_GENERATED:
            return f"Low entropy password generated: {event.entropy_bits:.1f} bits"
        return None
    
    @staticmethod
    def detect_high_volume(event: AuditEvent) -> str | None:
        """Detect unusually high generation volume (would query DB in production)"""
        # In production, query Redis/DB for count from same fingerprint
        # This is a simplified example
        return None
    
    @staticmethod
    def detect_pattern_abuse(event: AuditEvent) -> str | None:
        """Detect suspicious generation patterns"""
        if event.event_type == AuditEventType.BATCH_GENERATION:
            if event.password_length > 100:
                return f"Unusually long passwords requested: {event.password_length}"
        return None


# Global audit logger instance
audit_logger = (AuditLogger()
    .add_anomaly_detector(AuditLogger.detect_weak_password)
    .add_anomaly_detector(AuditLogger.detect_pattern_abuse))
