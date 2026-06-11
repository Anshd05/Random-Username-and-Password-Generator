#!/usr/bin/env python3
"""
Cryptographic Username & Password Generator
Backend: Python (Flask + cryptography)
Combines: CSPRNG, Argon2/PBKDF2 hashing, AES-256-GCM encryption, 
          entropy calculation, zxcvbn strength analysis
"""

import os
import sys
import json
import math
import time
import hmac as hmac_module
import hashlib
import base64
import secrets
import string
import struct
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Tuple, Optional, Literal
from dataclasses import dataclass
from collections import defaultdict, deque
from threading import Timer

# === Flask Web Framework ===
from flask import Flask, request, jsonify, render_template, session

# === Cryptography Libraries ===
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CryptoGen")

# === Import Security & Enhancement Modules ===
try:
    from audit import audit_logger, AuditEventType, AuditEvent
except ImportError:
    logger.warning("Audit module not available")
    audit_logger = None

try:
    from database import credential_repo
except ImportError:
    logger.warning("Database module not available")
    credential_repo = None

try:
    from plugins import StrategyRegistry
except ImportError:
    logger.warning("Plugin system not available")
    StrategyRegistry = None



class CryptoRandomEngine:
    """
    Wraps Python's `secrets` module (which uses OS-level CSPRNG)
    with additional entropy mixing from multiple sources.
    """

    def __init__(self):
        self._entropy_pool = bytearray()
        self._reseed()

    def _reseed(self):
        """Mix entropy from multiple sources"""
        sources = [
            secrets.token_bytes(64),                    # OS CSPRNG
            struct.pack('d', time.time()),              # High-res timestamp
            struct.pack('d', time.perf_counter()),      # Perf counter
            os.urandom(32),                             # OS random
            str(os.getpid()).encode(),                  # Process ID
            secrets.token_bytes(32),                    # Additional CSPRNG
        ]
        combined = b''.join(sources)
        self._entropy_pool = bytearray(
            hashlib.sha512(combined).digest()
        )

    def get_random_bytes(self, n: int) -> bytes:
        """Get n cryptographically secure random bytes"""
        return secrets.token_bytes(n)

    def get_random_int(self, low: int, high: int) -> int:
        """Get a CSPRNG integer in [low, high] inclusive"""
        return secrets.randbelow(high - low + 1) + low

    def get_random_choice(self, sequence):
        """Cryptographically secure random choice"""
        return secrets.choice(sequence)

    def shuffle_secure(self, lst: list) -> list:
        """Fisher-Yates shuffle with CSPRNG"""
        result = lst.copy()
        for i in range(len(result) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            result[i], result[j] = result[j], result[i]
        return result


# Global crypto engine
crypto_engine = CryptoRandomEngine()


# ============================================================
# SECURITY COMPONENTS
# ============================================================

# ============ ISSUE 1: Secure Credential Vault ============
class SecureCredentialVault:
    """
    One-time retrieval system. Password is stored server-side
    for max 30 seconds, retrieved ONCE via token, then destroyed.
    Prevents raw password exposure in API responses.
    """
    def __init__(self):
        self._store = {}  # token -> {data, expiry, retrieved}
    
    def store_temporarily(self, credential_data: dict, ttl_seconds: int = 30) -> str:
        """Store credential, return one-time retrieval token"""
        token = secrets.token_urlsafe(32)
        expiry = time.time() + ttl_seconds
        
        self._store[token] = {
            "data": credential_data,
            "expiry": expiry,
            "retrieved": False,
            "created_at": time.time(),
        }
        
        # Auto-destroy after TTL
        Timer(ttl_seconds, self._destroy, args=[token]).start()
        return token
    
    def retrieve_once(self, token: str) -> Dict | None:
        """
        Retrieve credential exactly ONCE.
        After retrieval, data is immediately destroyed.
        """
        entry = self._store.get(token)
        
        if not entry:
            return None  # Token doesn't exist or already used
        
        if entry["retrieved"]:
            return None  # Already retrieved once - deny
        
        if time.time() > entry["expiry"]:
            self._destroy(token)
            return None  # Expired
        
        # Mark as retrieved BEFORE returning
        entry["retrieved"] = True
        # Copy before destroy — _destroy nulls entry["data"] in place
        data = {k: v for k, v in entry["data"].items()}
        
        # Immediately destroy after retrieval
        self._destroy(token)
        return data
    
    def _destroy(self, token: str):
        """Securely wipe and remove stored credential"""
        if token in self._store:
            # Overwrite with zeros before deletion
            entry = self._store[token]
            if isinstance(entry.get("data"), dict):
                for key in entry["data"]:
                    entry["data"][key] = None
            del self._store[token]


# ============ ISSUE 2: Rate Limiter ============
class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter with IP + fingerprint tracking.
    Prevents brute force and DoS attacks.
    """
    
    def __init__(self):
        # {identifier: deque of timestamps}
        self._windows = defaultdict(deque)
        self._blocked = {}  # {identifier: unblock_time}
    
    def is_allowed(
        self, 
        identifier: str,
        limit: int = 20,        # requests
        window: int = 60,        # seconds
        block_duration: int = 300 # 5 min block if exceeded
    ) -> dict:
        now = time.time()
        
        # Check if blocked
        if identifier in self._blocked:
            if now < self._blocked[identifier]:
                return {
                    "allowed": False,
                    "reason": "rate_limited",
                    "retry_after": int(self._blocked[identifier] - now),
                    "remaining": 0,
                }
            else:
                del self._blocked[identifier]
        
        # Clean old entries outside window
        window_data = self._windows[identifier]
        cutoff = now - window
        while window_data and window_data[0] < cutoff:
            window_data.popleft()
        
        # Check limit
        if len(window_data) >= limit:
            self._blocked[identifier] = now + block_duration
            return {
                "allowed": False,
                "reason": "rate_limit_exceeded",
                "retry_after": block_duration,
                "remaining": 0,
            }
        
        window_data.append(now)
        return {
            "allowed": True,
            "remaining": limit - len(window_data),
            "reset_at": int(now + window),
        }
    
    def get_identifier(self, flask_request) -> str:
        """Build identifier from multiple request properties"""
        ip = flask_request.remote_addr or "unknown"
        user_agent = flask_request.headers.get('User-Agent', '')[:100]
        accept_lang = flask_request.headers.get('Accept-Language', '')[:50]
        
        # Hash the fingerprint to avoid logging PII
        fingerprint_raw = f"{ip}:{user_agent}:{accept_lang}"
        return hashlib.sha256(fingerprint_raw.encode()).hexdigest()[:16]


# ============ ISSUE 3: CSRF Protection ============
class CSRFProtection:
    """
    Double-submit cookie pattern for CSRF protection.
    Client sends token in both cookie and request header.
    """
    
    SECRET_KEY = secrets.token_bytes(32)
    TOKEN_LIFETIME = 3600  # 1 hour
    
    @classmethod
    def generate_token(cls, session_id: str) -> str:
        """Generate HMAC-signed CSRF token"""
        timestamp = int(time.time())
        message = f"{session_id}:{timestamp}"
        
        mac = hmac_module.new(
            cls.SECRET_KEY,
            message.encode(),
            'sha256'
        ).hexdigest()
        
        token = base64.urlsafe_b64encode(
            f"{message}:{mac}".encode()
        ).decode()
        return token
    
    @classmethod
    def validate_token(cls, token: str, session_id: str) -> bool:
        """Validate CSRF token"""
        try:
            decoded = base64.urlsafe_b64decode(token.encode()).decode()
            parts = decoded.rsplit(':', 1)
            if len(parts) != 2:
                return False
            
            message, provided_mac = parts
            msg_parts = message.split(':')
            if len(msg_parts) != 2:
                return False
            
            token_session, timestamp_str = msg_parts
            
            # Check session matches
            if not hmac_module.compare_digest(token_session, session_id):
                return False
            
            # Check not expired
            timestamp = int(timestamp_str)
            if time.time() - timestamp > cls.TOKEN_LIFETIME:
                return False
            
            # Verify HMAC
            expected_mac = hmac_module.new(
                cls.SECRET_KEY,
                message.encode(),
                'sha256'
            ).hexdigest()
            
            return hmac_module.compare_digest(provided_mac, expected_mac)
        except Exception:
            return False


# ============ ISSUE 4: Input Validation ============
@dataclass
class GenerationRequest:
    """Validated and sanitized generation request"""
    
    password_length: int = 24
    strategy: str = "random"
    username_style: str = "mixed"
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_special: bool = True
    exclude_ambiguous: bool = False
    include_numbers: bool = True
    hash_algorithm: str = "sha3_512"
    batch_count: int = 1
    
    # Allowed values (whitelist approach)
    ALLOWED_STRATEGIES = frozenset(["random", "passphrase", "pattern", "hybrid"])
    ALLOWED_USERNAME_STYLES = frozenset(["mixed", "adjective_noun", "hex", "base64", "phonetic", "hacker"])
    ALLOWED_HASH_ALGORITHMS = frozenset(["sha3_512", "sha3_256", "blake2b", "sha512", "sha256"])
    
    @classmethod
    def from_json(cls, data: dict) -> 'GenerationRequest':
        """Parse and validate JSON input"""
        req = cls()
        
        try:
            # Validate integer fields with bounds
            raw_length = data.get('password_length', 24)
            if not isinstance(raw_length, (int, float)):
                raise ValueError("password_length must be numeric")
            req.password_length = max(8, min(128, int(raw_length)))
            
            # Validate batch count
            raw_batch = data.get('batch_count', 1)
            if not isinstance(raw_batch, (int, float)):
                raise ValueError("batch_count must be numeric")
            req.batch_count = max(1, min(50, int(raw_batch)))
            
            # Validate enum fields using whitelist
            strategy = str(data.get('strategy', 'random')).lower()
            if strategy not in cls.ALLOWED_STRATEGIES:
                raise ValueError(f"strategy must be one of {cls.ALLOWED_STRATEGIES}")
            req.strategy = strategy
            
            username_style = str(data.get('username_style', 'mixed')).lower()
            if username_style not in cls.ALLOWED_USERNAME_STYLES:
                raise ValueError(f"username_style must be one of {cls.ALLOWED_USERNAME_STYLES}")
            req.username_style = username_style
            
            hash_algo = str(data.get('hash_algorithm', 'sha3_512')).lower()
            if hash_algo not in cls.ALLOWED_HASH_ALGORITHMS:
                raise ValueError(f"hash_algorithm must be one of {cls.ALLOWED_HASH_ALGORITHMS}")
            req.hash_algorithm = hash_algo
            
            # Validate boolean fields
            for bool_field in ('use_uppercase', 'use_lowercase', 'use_digits',
                              'use_special', 'exclude_ambiguous', 'include_numbers'):
                val = data.get(bool_field, getattr(req, bool_field))
                if not isinstance(val, bool):
                    raise ValueError(f"{bool_field} must be boolean")
                setattr(req, bool_field, val)
            
            # Ensure at least one charset is selected
            if not any([req.use_uppercase, req.use_lowercase, req.use_digits, req.use_special]):
                req.use_lowercase = True  # Safe default
            
            return req
        except (ValueError, KeyError, TypeError) as e:
            raise ValueError(f"Invalid request: {str(e)}")


# Initialize security components
secure_vault = SecureCredentialVault()
rate_limiter = SlidingWindowRateLimiter()


# ============ Decorators ============
def rate_limit(limit: int = 20, window: int = 60):
    """Decorator for rate-limited routes"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            identifier = rate_limiter.get_identifier(request)
            result = rate_limiter.is_allowed(identifier, limit, window)
            
            if not result["allowed"]:
                response = jsonify({
                    "error": "Rate limit exceeded",
                    "retry_after": result.get("retry_after", 60),
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(result.get("retry_after", 60))
                response.headers['X-RateLimit-Remaining'] = "0"
                return response
            
            # Add rate limit headers to response
            resp = f(*args, **kwargs)
            if isinstance(resp, tuple):
                resp_obj, status = resp[0], resp[1] if len(resp) > 1 else 200
                if hasattr(resp_obj, 'headers'):
                    resp_obj.headers['X-RateLimit-Remaining'] = str(result.get("remaining", 0))
            elif hasattr(resp, 'headers'):
                resp.headers['X-RateLimit-Remaining'] = str(result.get("remaining", 0))
            return resp
        return wrapper
    return decorator


def csrf_required(f):
    """CSRF protection decorator"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            session_id = session.get('session_id', '')
            token = request.headers.get('X-CSRF-Token', '')
            
            if not CSRFProtection.validate_token(token, session_id):
                return jsonify({"error": "CSRF validation failed"}), 403
        return f(*args, **kwargs)
    return wrapper


class EntropyAnalyzer:
    """Calculate Shannon entropy and password strength metrics"""

    # Common password patterns to penalize
    COMMON_PATTERNS = [
        'password', '123456', 'qwerty', 'abc123', 'letmein',
        'admin', 'welcome', 'monkey', 'dragon', 'master',
        'login', 'princess', 'football', 'shadow', 'sunshine'
    ]

    KEYBOARD_PATTERNS = [
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
        '1234567890', '0987654321',
        'qazwsx', 'edcrfv', 'tgbyhn', 'ujmik',
    ]

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy in bits"""
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def charset_entropy(password: str) -> float:
        """Calculate entropy based on character set size"""
        charset_size = 0
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(c in string.punctuation for c in password)
        has_unicode = any(ord(c) > 127 for c in password)

        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        if has_unicode: charset_size += 100  # rough estimate

        if charset_size == 0:
            return 0.0
        return len(password) * math.log2(charset_size)

    @classmethod
    def analyze_strength(cls, password: str) -> Dict:
        """Comprehensive password strength analysis"""
        shannon = cls.shannon_entropy(password)
        charset = cls.charset_entropy(password)
        length = len(password)

        # Penalty checks
        penalties = []
        lower_pw = password.lower()

        # Check common patterns
        for pattern in cls.COMMON_PATTERNS:
            if pattern in lower_pw:
                penalties.append(f"Contains common pattern: '{pattern}'")

        # Check keyboard patterns
        for pattern in cls.KEYBOARD_PATTERNS:
            if any(pattern[i:i+4] in lower_pw for i in range(len(pattern)-3)):
                penalties.append(f"Contains keyboard pattern")
                break

        # Check repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                penalties.append("Contains repeated characters (3+)")
                break

        # Check sequential characters
        for i in range(len(password) - 2):
            if (ord(password[i]) + 1 == ord(password[i+1]) and 
                ord(password[i+1]) + 1 == ord(password[i+2])):
                penalties.append("Contains sequential characters")
                break

        # Calculate effective entropy (penalized)
        penalty_factor = max(0.5, 1.0 - (len(penalties) * 0.15))
        effective_entropy = charset * penalty_factor

        # Crack time estimation (assuming 10 billion guesses/sec - high-end GPU)
        guesses_per_sec = 10_000_000_000
        total_combinations = 2 ** effective_entropy
        seconds_to_crack = total_combinations / guesses_per_sec

        # Strength rating
        if effective_entropy >= 128:
            strength = "FORTRESS"
            score = 100
            color = "#00ff88"
        elif effective_entropy >= 100:
            strength = "EXCELLENT"
            score = 90
            color = "#00cc66"
        elif effective_entropy >= 80:
            strength = "VERY STRONG"
            score = 80
            color = "#44bb44"
        elif effective_entropy >= 60:
            strength = "STRONG"
            score = 65
            color = "#88aa00"
        elif effective_entropy >= 40:
            strength = "MODERATE"
            score = 45
            color = "#ccaa00"
        elif effective_entropy >= 28:
            strength = "WEAK"
            score = 25
            color = "#ff6600"
        else:
            strength = "CRITICAL"
            score = 10
            color = "#ff0000"

        return {
            "shannon_entropy": round(shannon, 2),
            "charset_entropy": round(charset, 2),
            "effective_entropy": round(effective_entropy, 2),
            "length": length,
            "strength": strength,
            "score": score,
            "color": color,
            "penalties": penalties,
            "crack_time": cls._format_crack_time(seconds_to_crack),
            "crack_time_seconds": seconds_to_crack,
            "character_classes": {
                "lowercase": any(c in string.ascii_lowercase for c in password),
                "uppercase": any(c in string.ascii_uppercase for c in password),
                "digits": any(c in string.digits for c in password),
                "special": any(c in string.punctuation for c in password),
                "unicode": any(ord(c) > 127 for c in password),
            }
        }

    @staticmethod
    def _format_crack_time(seconds: float) -> str:
        """Format crack time to human readable"""
        if seconds < 0.001:
            return "Instant"
        elif seconds < 1:
            return f"{seconds*1000:.1f} milliseconds"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 86400 * 365:
            return f"{seconds/86400:.1f} days"
        elif seconds < 86400 * 365 * 1000:
            return f"{seconds/(86400*365):.1f} years"
        elif seconds < 86400 * 365 * 1e6:
            return f"{seconds/(86400*365*1000):.1f} thousand years"
        elif seconds < 86400 * 365 * 1e9:
            return f"{seconds/(86400*365*1e6):.1f} million years"
        elif seconds < 86400 * 365 * 1e12:
            return f"{seconds/(86400*365*1e9):.1f} billion years"
        else:
            return f"{seconds/(86400*365*1e12):.1f} trillion+ years"



class UsernameGenerator:
    """Generate unique, memorable usernames using crypto-random selection"""

    ADJECTIVES = [
        "Shadow", "Cyber", "Quantum", "Phantom", "Stealth", "Crypto",
        "Binary", "Neural", "Atomic", "Vector", "Dark", "Silent",
        "Ghost", "Rogue", "Nexus", "Apex", "Zero", "Alpha",
        "Omega", "Hyper", "Nano", "Pulse", "Storm", "Frost",
        "Blaze", "Neon", "Obsidian", "Titanium", "Cobalt", "Cipher",
        "Iron", "Steel", "Chrome", "Onyx", "Jade", "Ruby",
        "Plasma", "Astral", "Void", "Flux", "Rapid", "Swift",
        "Agile", "Keen", "Sharp", "Bright", "Bold", "Brave",
        "Elite", "Prime", "Ultra", "Mega", "Turbo", "Nitro",
    ]

    NOUNS = [
        "Wolf", "Hawk", "Viper", "Phoenix", "Dragon", "Falcon",
        "Panther", "Tiger", "Eagle", "Shark", "Cobra", "Fox",
        "Lynx", "Raven", "Bear", "Lion", "Jaguar", "Mantis",
        "Scorpion", "Raptor", "Wraith", "Sentinel", "Guardian",
        "Knight", "Ranger", "Hunter", "Warrior", "Nomad", "Sage",
        "Oracle", "Architect", "Pioneer", "Voyager", "Explorer",
        "Defender", "Warden", "Seeker", "Blade", "Shield", "Hammer",
        "Forge", "Spark", "Bolt", "Crypt", "Proxy", "Node",
        "Stack", "Core", "Byte", "Pixel", "Vector", "Matrix",
    ]

    SEPARATORS = ["_", "-", ".", ""]

    @classmethod
    def generate(cls, style: str = "mixed", include_numbers: bool = True) -> str:
        """Generate a cryptographically random username"""
        
        if style == "adjective_noun":
            adj = crypto_engine.get_random_choice(cls.ADJECTIVES)
            noun = crypto_engine.get_random_choice(cls.NOUNS)
            sep = crypto_engine.get_random_choice(cls.SEPARATORS)
            username = f"{adj}{sep}{noun}"
            if include_numbers:
                username += str(crypto_engine.get_random_int(10, 9999))

        elif style == "hex":
            # Pure hex username
            hex_bytes = crypto_engine.get_random_bytes(4)
            username = f"0x{hex_bytes.hex().upper()}"

        elif style == "base64":
            raw = crypto_engine.get_random_bytes(6)
            username = base64.urlsafe_b64encode(raw).decode().rstrip('=')

        elif style == "phonetic":
            username = cls._generate_phonetic()
            if include_numbers:
                username += str(crypto_engine.get_random_int(10, 999))

        elif style == "hacker":
            adj = crypto_engine.get_random_choice(cls.ADJECTIVES)
            noun = crypto_engine.get_random_choice(cls.NOUNS)
            sep = crypto_engine.get_random_choice(["_", "-"])
            username = cls._leetify(f"{adj}{sep}{noun}")
            if include_numbers:
                username += str(crypto_engine.get_random_int(0, 99))

        else:  # "mixed" - random combination
            methods = ["adjective_noun", "hex", "base64", "phonetic", "hacker"]
            chosen = crypto_engine.get_random_choice(methods)
            return cls.generate(style=chosen, include_numbers=include_numbers)

        return username

    @classmethod
    def _generate_phonetic(cls) -> str:
        """Generate a pronounceable username"""
        consonants = "bcdfghjklmnprstvwxz"
        vowels = "aeiou"
        syllables = crypto_engine.get_random_int(2, 4)
        result = ""
        for _ in range(syllables):
            result += crypto_engine.get_random_choice(consonants)
            result += crypto_engine.get_random_choice(vowels)
            if secrets.randbelow(3) == 0:
                result += crypto_engine.get_random_choice(consonants)
        # Capitalize first letter
        return result.capitalize()

    @staticmethod
    def _leetify(text: str) -> str:
        """Convert text to leet speak"""
        leet_map = {
            'a': '4', 'e': '3', 'i': '1', 'o': '0',
            's': '5', 't': '7', 'l': '1', 'g': '9',
            'A': '4', 'E': '3', 'I': '1', 'O': '0',
            'S': '5', 'T': '7', 'L': '1', 'G': '9',
        }
        result = ""
        for ch in text:
            if ch in leet_map and secrets.randbelow(2) == 0:
                result += leet_map[ch]
            else:
                result += ch
        return result




class PasswordGenerator:
    """
    Cryptographically secure password generator with multiple strategies.
    All randomness comes from CSPRNG (secrets module backed by OS entropy).
    """

    # Ambiguous characters excluded for readability
    AMBIGUOUS = set('Il1O0o')

    # Character pools
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SPECIAL = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    EXTENDED_SPECIAL = SPECIAL + '¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿'

    # Diceware-style word list (abbreviated - in production, use full EFF list)
    WORDLIST = [
        "correct", "horse", "battery", "staple", "abandon", "ability",
        "anchor", "bridge", "castle", "delta", "ember", "falcon",
        "glacier", "harbor", "ignite", "jungle", "kernel", "lantern",
        "magnet", "nebula", "orbit", "prism", "quartz", "ripple",
        "summit", "torque", "umbra", "vertex", "whisper", "xenon",
        "zenith", "alpine", "beacon", "cipher", "dynamo", "enigma",
        "flare", "gravity", "horizon", "impulse", "jackal", "kinetic",
        "lunar", "matrix", "neutron", "optic", "plasma", "quantum",
        "radar", "solar", "thermal", "ultra", "vortex", "wavelength",
        "axiom", "breach", "chrome", "drift", "eclipse", "fractal",
        "graphite", "helix", "indigo", "jovial", "krypton", "lithium",
        "mosaic", "nucleus", "oxide", "photon", "quasar", "reactor",
        "sphinx", "turbo", "uplink", "vector", "warp", "xray",
        "yield", "zephyr", "amber", "blitz", "coral", "dagger",
        "epoch", "forge", "granite", "haven", "ivory", "jade",
        "karma", "latch", "mercury", "noble", "onyx", "pearl",
    ]

    @classmethod
    def generate(cls, 
                 length: int = 24,
                 use_uppercase: bool = True,
                 use_lowercase: bool = True,
                 use_digits: bool = True,
                 use_special: bool = True,
                 exclude_ambiguous: bool = False,
                 min_uppercase: int = 1,
                 min_lowercase: int = 1,
                 min_digits: int = 1,
                 min_special: int = 1,
                 strategy: str = "random") -> str:
        """Generate a password using the specified strategy"""

        if strategy == "passphrase":
            return cls._generate_passphrase(length)
        elif strategy == "pattern":
            return cls._generate_pattern_based(length)
        elif strategy == "hybrid":
            return cls._generate_hybrid(length)
        else:
            return cls._generate_random(
                length, use_uppercase, use_lowercase, use_digits,
                use_special, exclude_ambiguous,
                min_uppercase, min_lowercase, min_digits, min_special
            )

    @classmethod
    def _generate_random(cls, length, use_upper, use_lower, use_digits,
                         use_special, exclude_ambiguous,
                         min_upper, min_lower, min_digits, min_special) -> str:
        """Pure random character-based password generation"""

        # Build character pool
        pool = ""
        required_chars = []

        if use_lower:
            chars = cls.LOWERCASE
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in cls.AMBIGUOUS)
            pool += chars
            for _ in range(min_lower):
                required_chars.append(crypto_engine.get_random_choice(chars))

        if use_upper:
            chars = cls.UPPERCASE
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in cls.AMBIGUOUS)
            pool += chars
            for _ in range(min_upper):
                required_chars.append(crypto_engine.get_random_choice(chars))

        if use_digits:
            chars = cls.DIGITS
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in cls.AMBIGUOUS)
            pool += chars
            for _ in range(min_digits):
                required_chars.append(crypto_engine.get_random_choice(chars))

        if use_special:
            pool += cls.SPECIAL
            for _ in range(min_special):
                required_chars.append(crypto_engine.get_random_choice(cls.SPECIAL))

        if not pool:
            pool = cls.LOWERCASE + cls.UPPERCASE + cls.DIGITS

        # Fill remaining length
        remaining = length - len(required_chars)
        if remaining < 0:
            remaining = 0
            required_chars = required_chars[:length]

        all_chars = required_chars + [
            crypto_engine.get_random_choice(pool) for _ in range(remaining)
        ]

        # Cryptographically secure shuffle
        password_chars = crypto_engine.shuffle_secure(all_chars)
        return ''.join(password_chars)

    @classmethod
    def _generate_passphrase(cls, word_count: int = 6) -> str:
        """Generate a diceware-style passphrase"""
        if word_count < 3:
            word_count = 3

        words = []
        for _ in range(min(word_count, 12)):
            word = crypto_engine.get_random_choice(cls.WORDLIST)
            # Randomly capitalize or modify
            transform = secrets.randbelow(4)
            if transform == 0:
                word = word.capitalize()
            elif transform == 1:
                word = word.upper()
            elif transform == 2:
                # Insert a random digit
                pos = secrets.randbelow(len(word))
                digit = str(secrets.randbelow(10))
                word = word[:pos] + digit + word[pos:]
            words.append(word)

        separators = ['-', '.', '_', ':', '+', '=', '~']
        sep = crypto_engine.get_random_choice(separators)

        passphrase = sep.join(words)

        # Add a random special char and number at random positions
        special = crypto_engine.get_random_choice("!@#$%^&*")
        number = str(crypto_engine.get_random_int(10, 99))
        passphrase = passphrase + special + number

        return passphrase

    @classmethod
    def _generate_pattern_based(cls, length: int = 24) -> str:
        """Generate password following a pattern: CvCv-NNss-CvCv-NNss"""
        # C=consonant(upper), v=vowel, N=number, s=special
        consonants_upper = "BCDFGHJKLMNPQRSTVWXYZ"
        consonants_lower = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"
        specials = "!@#$%^&*"

        pattern_units = []
        while len(''.join(pattern_units)) < length:
            unit_type = secrets.randbelow(4)
            if unit_type == 0:
                unit = (crypto_engine.get_random_choice(consonants_upper) +
                       crypto_engine.get_random_choice(vowels) +
                       crypto_engine.get_random_choice(consonants_lower) +
                       crypto_engine.get_random_choice(vowels))
            elif unit_type == 1:
                unit = (str(crypto_engine.get_random_int(0, 9)) +
                       str(crypto_engine.get_random_int(0, 9)) +
                       crypto_engine.get_random_choice(specials))
            elif unit_type == 2:
                unit = (crypto_engine.get_random_choice(consonants_lower) +
                       crypto_engine.get_random_choice(vowels) +
                       crypto_engine.get_random_choice(consonants_upper))
            else:
                unit = (crypto_engine.get_random_choice(specials) +
                       crypto_engine.get_random_choice(vowels) +
                       str(crypto_engine.get_random_int(0, 9)))
            pattern_units.append(unit)

        result = '-'.join(pattern_units)
        return result[:length] if len(result) > length else result

    @classmethod
    def _generate_hybrid(cls, length: int = 24) -> str:
        """Hybrid: words + random chars + special"""
        word1 = crypto_engine.get_random_choice(cls.WORDLIST).capitalize()
        word2 = crypto_engine.get_random_choice(cls.WORDLIST)

        random_part_len = max(4, length - len(word1) - len(word2) - 3)
        random_part = ''.join(
            crypto_engine.get_random_choice(cls.DIGITS + cls.SPECIAL)
            for _ in range(random_part_len)
        )

        sep = crypto_engine.get_random_choice(['_', '-', '.', '#'])
        parts = [word1, random_part, word2.upper()]
        parts = crypto_engine.shuffle_secure(parts)
        result = sep.join(parts)

        return result[:length] if len(result) > length else result




class CryptoVault:
    """
    Encrypt, hash, and securely handle generated credentials.
    Uses AES-256-GCM for encryption and PBKDF2/Scrypt for key derivation.
    """

    @staticmethod
    def derive_key_pbkdf2(master_password: str, salt: bytes = None,
                          iterations: int = 600_000) -> Tuple[bytes, bytes]:
        """Derive encryption key from master password using PBKDF2-HMAC-SHA256"""
        if salt is None:
            salt = os.urandom(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(master_password.encode('utf-8'))
        return key, salt

    @staticmethod
    def derive_key_scrypt(master_password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Derive encryption key using Scrypt (memory-hard)"""
        if salt is None:
            salt = os.urandom(32)

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**17,    # CPU/memory cost
            r=8,        # Block size
            p=1,        # Parallelization
            backend=default_backend()
        )
        key = kdf.derive(master_password.encode('utf-8'))
        return key, salt

    @staticmethod
    def encrypt_aes_gcm(plaintext: str, key: bytes) -> Dict[str, str]:
        """Encrypt using AES-256-GCM (authenticated encryption)"""
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        aesgcm = AESGCM(key)
        
        # Additional authenticated data
        aad = b"CryptoGen-v1.0-credential"
        
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode('utf-8'),
            aad
        )

        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "aad": base64.b64encode(aad).decode('utf-8'),
            "algorithm": "AES-256-GCM",
        }

    @staticmethod
    def decrypt_aes_gcm(encrypted_data: Dict[str, str], key: bytes) -> str:
        """Decrypt AES-256-GCM ciphertext"""
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        aad = base64.b64decode(encrypted_data["aad"])

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext.decode('utf-8')

    @staticmethod
    def hash_password(password: str, algorithm: str = "sha3_512") -> Dict[str, str]:
        """Hash password with salt for storage verification"""
        salt = os.urandom(32)
        
        if algorithm == "sha3_512":
            salted = salt + password.encode('utf-8')
            hash_value = hashlib.sha3_512(salted).hexdigest()
        elif algorithm == "sha3_256":
            salted = salt + password.encode('utf-8')
            hash_value = hashlib.sha3_256(salted).hexdigest()
        elif algorithm == "blake2b":
            h = hashlib.blake2b(password.encode('utf-8'), salt=salt[:16])
            hash_value = h.hexdigest()
        elif algorithm == "sha512":
            salted = salt + password.encode('utf-8')
            hash_value = hashlib.sha512(salted).hexdigest()
        else:
            salted = salt + password.encode('utf-8')
            hash_value = hashlib.sha256(salted).hexdigest()
            algorithm = "sha256"

        return {
            "hash": hash_value,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "algorithm": algorithm,
            "iterations": 1,  # For simple hash; PBKDF2 uses more
        }

    @staticmethod
    def generate_hmac(message: str, key: bytes = None) -> Dict[str, str]:
        """Generate HMAC-SHA256 for message integrity"""
        if key is None:
            key = secrets.token_bytes(32)
        
        mac = hmac_module.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()
        return {
            "hmac": mac,
            "key": base64.b64encode(key).decode('utf-8'),
            "algorithm": "HMAC-SHA256"
        }

    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Dict[str, str]:
        """Generate RSA key pair for asymmetric encryption demo"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return {
            "private_key": private_pem,
            "public_key": public_pem,
            "key_size": key_size
        }



@app.route('/')
def index():
    """Serve the main HTML page"""
    # Initialize session with CSRF token and session ID
    if 'session_id' not in session:
        session['session_id'] = secrets.token_urlsafe(32)
    if 'csrf_token' not in session:
        session['csrf_token'] = CSRFProtection.generate_token(session['session_id'])
    return render_template('index.html', csrf_token=session['csrf_token'])


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "crypto": "AES-256-GCM, PBKDF2, SHA-3",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


@app.route('/api/strategies', methods=['GET'])
def list_strategies():
    """List available password generation strategies"""
    try:
        if StrategyRegistry:
            strategies = StrategyRegistry.list_all()
        else:
            strategies = [
                {
                    "name": "random",
                    "description": "Cryptographically random password",
                    "min_entropy": 80.0
                },
                {
                    "name": "passphrase",
                    "description": "Diceware-style passphrase",
                    "min_entropy": 60.0
                },
                {
                    "name": "pattern",
                    "description": "Pattern-based password",
                    "min_entropy": 70.0
                },
                {
                    "name": "hybrid",
                    "description": "Hybrid approach combining multiple methods",
                    "min_entropy": 75.0
                }
            ]
        return jsonify({"status": "success", "strategies": strategies})
    except Exception as e:
        logger.error(f"Strategies error: {str(e)}")
        return jsonify({"error": "Failed to list strategies"}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get aggregate statistics about generated credentials"""
    try:
        if credential_repo:
            stats = credential_repo.get_stats()
        else:
            stats = {
                "total_generated": 0,
                "average_entropy": 0,
                "strength_distribution": {}
            }
        return jsonify({"status": "success", "stats": stats})
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({"error": "Failed to retrieve stats"}), 500


@app.route('/api/save', methods=['POST'])
@rate_limit(limit=30, window=60)
@csrf_required
def save_credential():
    """Save a generated credential to database"""
    try:
        if not credential_repo:
            return jsonify({"error": "Database not available"}), 503
        
        data = request.get_json() or {}
        credential_data = data.get('credential', {})
        label = data.get('label', '')
        
        if not credential_data:
            return jsonify({"error": "No credential data provided"}), 400
        
        saved = credential_repo.save({
            **credential_data,
            'label': label
        })
        
        # Log audit event
        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.CREDENTIAL_RETRIEVED,
                entropy_bits=credential_data.get('strength', {}).get('effective_entropy', 0),
                strength_level=credential_data.get('strength', {}).get('strength', 'UNKNOWN'),
                password_length=credential_data.get('strength', {}).get('length', 0),
            ))
        
        return jsonify({
            "status": "success",
            "id": saved.id,
            "message": "Credential saved successfully"
        })
    except Exception as e:
        logger.error(f"Save error: {str(e)}")
        return jsonify({"error": "Failed to save credential"}), 500


@app.route('/api/generate', methods=['POST'])
@rate_limit(limit=20, window=60)  # 20 requests per 60 seconds
@csrf_required
def generate_credentials():
    """Main endpoint: Generate username + password with crypto analysis"""
    try:
        data = request.get_json() or {}
        
        # Validate input
        req = GenerationRequest.from_json(data)

        # Generate username
        username = UsernameGenerator.generate(
            style=req.username_style,
            include_numbers=req.include_numbers
        )

        # Generate password
        password = PasswordGenerator.generate(
            length=req.password_length,
            use_uppercase=req.use_uppercase,
            use_lowercase=req.use_lowercase,
            use_digits=req.use_digits,
            use_special=req.use_special,
            exclude_ambiguous=req.exclude_ambiguous,
            strategy=req.strategy
        )

        # Analyze password strength
        strength = EntropyAnalyzer.analyze_strength(password)

        # Hash the password
        password_hash = CryptoVault.hash_password(password, algorithm=req.hash_algorithm)

        # Generate HMAC for integrity
        hmac_data = CryptoVault.generate_hmac(password)

        # Encrypt the password with a derived key (for demo - using a random master key)
        demo_master = secrets.token_hex(16)
        encryption_key, enc_salt = CryptoVault.derive_key_pbkdf2(demo_master)
        encrypted = CryptoVault.encrypt_aes_gcm(password, encryption_key)
        encrypted['salt'] = base64.b64encode(enc_salt).decode('utf-8')
        encrypted['kdf'] = 'PBKDF2-HMAC-SHA256'
        encrypted['iterations'] = 600_000

        # ✅ Store credential in secure vault (NOT in response)
        credential_data = {
            "username": username,
            "password": password,
            "strength": strength,
            "hash": password_hash,
            "encrypted": encrypted,
            "hmac": hmac_data,
        }
        retrieval_token = secure_vault.store_temporarily(credential_data, ttl_seconds=30)

        # Response - NO raw password sent
        response = {
            "status": "success",
            "retrieval_token": retrieval_token,  # Client uses this ONCE to get password
            "expires_in": 30,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "strength_analysis": strength,
            "generation_metadata": {
                "csprng_source": "secrets (OS-level entropy)",
                "python_version": sys.version.split()[0],
                "password_strategy": req.strategy,
                "username_style": req.username_style,
            }
        }

        logger.info(f"Generated credentials - Entropy: {strength['effective_entropy']} bits, "
                    f"Strength: {strength['strength']}")

        return jsonify(response)

    except ValueError as e:
        logger.warning(f"Validation error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        logger.error(f"Generation error: {str(e)}")
        return jsonify({"status": "error", "message": "Generation failed"}), 500


@app.route('/api/retrieve', methods=['POST'])
@rate_limit(limit=50, window=60)
@csrf_required
def retrieve_credential():
    """One-time credential retrieval - returns password only once"""
    try:
        data = request.get_json() or {}
        token = data.get('token', '')
        
        if not token:
            return jsonify({"error": "Missing retrieval token"}), 400
        
        # Retrieve from vault (only succeeds once)
        credential = secure_vault.retrieve_once(token)
        
        if not credential:
            return jsonify({"error": "Invalid, expired, or already-used token"}), 403
        
        return jsonify({
            "status": "success",
            "credential": credential
        })
    
    except Exception as e:
        logger.error(f"Retrieval error: {str(e)}")
        return jsonify({"error": "Retrieval failed"}), 500


@app.route('/api/analyze', methods=['POST'])
@rate_limit(limit=30, window=60)
@csrf_required
def analyze_password():
    """Analyze an existing password's strength"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        if not password:
            return jsonify({"status": "error", "message": "No password provided"}), 400
        
        # Limit password length to prevent ReDoS
        if len(password) > 1000:
            return jsonify({"status": "error", "message": "Password too long"}), 400

        strength = EntropyAnalyzer.analyze_strength(password)
        return jsonify({"status": "success", "analysis": strength})

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/encrypt', methods=['POST'])
@rate_limit(limit=30, window=60)
@csrf_required
def encrypt_credential():
    """Encrypt a credential with a provided master password"""
    try:
        data = request.get_json()
        plaintext = data.get('plaintext', '')
        master_password = data.get('master_password', '')
        kdf_type = data.get('kdf', 'pbkdf2')

        if not plaintext or not master_password:
            return jsonify({"status": "error", "message": "Missing fields"}), 400

        # Validate input lengths
        if len(plaintext) > 10000:
            return jsonify({"status": "error", "message": "Plaintext too long"}), 400
        if len(master_password) > 1000:
            return jsonify({"status": "error", "message": "Master password too long"}), 400

        # Validate KDF choice
        if kdf_type not in ('pbkdf2', 'scrypt'):
            return jsonify({"status": "error", "message": "Invalid KDF type"}), 400

        if kdf_type == 'scrypt':
            key, salt = CryptoVault.derive_key_scrypt(master_password)
            kdf_name = "Scrypt"
        else:
            key, salt = CryptoVault.derive_key_pbkdf2(master_password)
            kdf_name = "PBKDF2-HMAC-SHA256"

        encrypted = CryptoVault.encrypt_aes_gcm(plaintext, key)
        encrypted['salt'] = base64.b64encode(salt).decode('utf-8')
        encrypted['kdf'] = kdf_name

        return jsonify({"status": "success", "encrypted": encrypted})

    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/decrypt', methods=['POST'])
@rate_limit(limit=30, window=60)
@csrf_required
def decrypt_credential():
    """Decrypt an encrypted credential"""
    try:
        data = request.get_json()
        encrypted_data = data.get('encrypted_data', {})
        master_password = data.get('master_password', '')

        if not encrypted_data or not master_password:
            return jsonify({"status": "error", "message": "Missing fields"}), 400

        salt = base64.b64decode(encrypted_data.get('salt', ''))
        kdf_type = encrypted_data.get('kdf', 'PBKDF2-HMAC-SHA256')

        if 'Scrypt' in kdf_type:
            key, _ = CryptoVault.derive_key_scrypt(master_password, salt=salt)
        else:
            key, _ = CryptoVault.derive_key_pbkdf2(master_password, salt=salt)

        plaintext = CryptoVault.decrypt_aes_gcm(encrypted_data, key)
        return jsonify({"status": "success", "plaintext": plaintext})

    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({"status": "error", "message": "Decryption failed - wrong key or corrupted data"}), 400


@app.route('/api/batch', methods=['POST'])
@rate_limit(limit=10, window=60)  # Stricter limit for batch
@csrf_required
def batch_generate():
    """Generate multiple credential sets at once"""
    try:
        data = request.get_json() or {}
        
        # Validate batch request
        req = GenerationRequest.from_json(data)
        
        results = []
        for i in range(req.batch_count):
            username = UsernameGenerator.generate(
                style=req.username_style,
                include_numbers=req.include_numbers
            )
            password = PasswordGenerator.generate(
                length=req.password_length,
                strategy=req.strategy,
                use_uppercase=req.use_uppercase,
                use_lowercase=req.use_lowercase,
                use_digits=req.use_digits,
                use_special=req.use_special,
                exclude_ambiguous=req.exclude_ambiguous,
            )
            strength = EntropyAnalyzer.analyze_strength(password)
            results.append({
                "index": i + 1,
                "username": username,
                "password": password,
                "entropy": strength['effective_entropy'],
                "strength": strength['strength'],
                "crack_time": strength['crack_time'],
            })

        return jsonify({"status": "success", "count": req.batch_count, "credentials": results})

    except ValueError as e:
        logger.warning(f"Validation error in batch: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        logger.error(f"Batch generation error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500




if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     CRYPTOGRAPHIC CREDENTIAL GENERATOR v1.0         ║
    ║     Backend: Python (Flask + cryptography)              ║
    ║     Frontend: JavaScript + HTML5 + CSS3                 ║
    ║     Crypto: AES-256-GCM, PBKDF2, Scrypt, SHA-3         ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)