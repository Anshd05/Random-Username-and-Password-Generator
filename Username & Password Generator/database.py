#!/usr/bin/env python3
"""
Secure Credential Storage with SQLAlchemy
IMPORTANT: We NEVER store plaintext passwords.
Only store: username, hashed_password, metadata, encrypted_vault_entry
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean,
    DateTime, Text, create_engine, Index, event
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.pool import StaticPool
from datetime import datetime
import uuid
import json

Base = declarative_base()


class StoredCredential(Base):
    """
    Secure credential storage model.
    NEVER stores plaintext passwords.
    """
    __tablename__ = 'credentials'
    
    # Identity
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    label = Column(String(255), nullable=True)  # e.g., "GitHub account"
    
    # Username (stored as-is, not sensitive)
    username = Column(String(255), nullable=False)
    
    # Password stored ONLY as hash + encrypted blob (never plaintext)
    password_hash = Column(Text, nullable=False)       # SHA3-512 hash
    password_salt = Column(Text, nullable=False)       # Base64 encoded salt
    hash_algorithm = Column(String(50), nullable=False)
    encrypted_vault = Column(Text, nullable=True)      # AES-256-GCM encrypted
    
    # Strength metadata (safe to store)
    entropy_bits = Column(Float, nullable=False)
    strength_level = Column(String(20), nullable=False)
    password_length = Column(Integer, nullable=False)
    generation_strategy = Column(String(50), nullable=False)
    crack_time_estimate = Column(String(100), nullable=True)
    
    # Security metadata
    character_classes = Column(Text, nullable=True)  # JSON string
    has_lowercase = Column(Boolean, default=False)
    has_uppercase = Column(Boolean, default=False)
    has_digits = Column(Boolean, default=False)
    has_special = Column(Boolean, default=False)
    
    # Audit trail
    last_accessed = Column(DateTime, nullable=True)
    access_count = Column(Integer, default=0)
    client_fingerprint = Column(String(64), nullable=True)  # Anonymized
    
    # Soft delete
    is_archived = Column(Boolean, default=False)
    archived_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_username', 'username'),
        Index('idx_created_at', 'created_at'),
        Index('idx_strength', 'strength_level'),
    )
    
    def archive(self):
        """Soft delete - mark as archived instead of actual delete"""
        self.is_archived = True
        self.archived_at = datetime.utcnow()
    
    def to_safe_dict(self) -> dict:
        """Return credential data WITHOUT sensitive fields"""
        return {
            "id": self.id,
            "label": self.label,
            "username": self.username,
            "created_at": self.created_at.isoformat(),
            "entropy_bits": self.entropy_bits,
            "strength_level": self.strength_level,
            "password_length": self.password_length,
            "generation_strategy": self.generation_strategy,
            "crack_time_estimate": self.crack_time_estimate,
            "has_lowercase": self.has_lowercase,
            "has_uppercase": self.has_uppercase,
            "has_digits": self.has_digits,
            "has_special": self.has_special,
            # NOTE: password_hash, password_salt, encrypted_vault OMITTED
        }


class CredentialRepository:
    """Repository pattern for credential operations"""
    
    def __init__(self, db_url: str = "sqlite:///credentials.db"):
        self.db_url = db_url
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
            poolclass=StaticPool if "sqlite" in db_url else None,
        )
        
        # Enable WAL mode for SQLite (better concurrency)
        if "sqlite" in db_url:
            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_connection, _):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA secure_delete=ON")  # Secure delete
                cursor.close()
        
        Base.metadata.create_all(engine)
        self.SessionLocal = sessionmaker(bind=engine)
    
    def get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()
    
    def save(self, credential_data: dict) -> StoredCredential:
        """Save a generated credential (without plaintext password)"""
        session = self.get_session()
        try:
            cred = StoredCredential(
                username=credential_data['username'],
                password_hash=credential_data['password_hash']['hash'],
                password_salt=credential_data['password_hash']['salt'],
                hash_algorithm=credential_data['password_hash']['algorithm'],
                entropy_bits=credential_data['strength']['effective_entropy'],
                strength_level=credential_data['strength']['strength'],
                password_length=credential_data['strength']['length'],
                generation_strategy=credential_data.get('strategy', 'random'),
                crack_time_estimate=credential_data['strength']['crack_time'],
                has_lowercase=credential_data['strength']['character_classes'].get('lowercase', False),
                has_uppercase=credential_data['strength']['character_classes'].get('uppercase', False),
                has_digits=credential_data['strength']['character_classes'].get('digits', False),
                has_special=credential_data['strength']['character_classes'].get('special', False),
                character_classes=json.dumps(credential_data['strength']['character_classes']),
            )
            session.add(cred)
            session.commit()
            session.close()
            return cred
        except Exception as e:
            session.rollback()
            session.close()
            raise e
    
    def get_all(self, include_archived: bool = False) -> list:
        """Get all credentials (safe fields only)"""
        session = self.get_session()
        try:
            query = session.query(StoredCredential)
            if not include_archived:
                query = query.filter(StoredCredential.is_archived == False)
            results = [c.to_safe_dict() for c in query.order_by(StoredCredential.created_at.desc()).all()]
            session.close()
            return results
        except Exception as e:
            session.close()
            raise e
    
    def get_by_id(self, cred_id: str) -> dict | None:
        """Get credential by ID (safe fields only)"""
        session = self.get_session()
        try:
            cred = session.query(StoredCredential).filter(StoredCredential.id == cred_id).first()
            if cred:
                result = cred.to_safe_dict()
            else:
                result = None
            session.close()
            return result
        except Exception as e:
            session.close()
            raise e
    
    def get_stats(self) -> dict:
        """Get aggregate statistics"""
        from sqlalchemy import func
        session = self.get_session()
        try:
            total = session.query(func.count(StoredCredential.id)).scalar()
            avg_entropy = session.query(func.avg(StoredCredential.entropy_bits)).scalar()
            strength_dist = (
                session.query(StoredCredential.strength_level, func.count())
                .group_by(StoredCredential.strength_level).all()
            )
            
            session.close()
            return {
                "total_generated": total or 0,
                "average_entropy": round(avg_entropy or 0, 2),
                "strength_distribution": dict(strength_dist) if strength_dist else {},
            }
        except Exception as e:
            session.close()
            raise e
    
    def archive(self, cred_id: str) -> bool:
        """Soft delete a credential"""
        session = self.get_session()
        try:
            cred = session.query(StoredCredential).filter(StoredCredential.id == cred_id).first()
            if cred:
                cred.archive()
                session.commit()
                session.close()
                return True
            session.close()
            return False
        except Exception as e:
            session.rollback()
            session.close()
            raise e


# Global repository instance
credential_repo = CredentialRepository()
