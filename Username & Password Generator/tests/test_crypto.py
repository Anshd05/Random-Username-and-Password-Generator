#!/usr/bin/env python3
"""
Comprehensive security-focused test suite for CryptoGen
"""

import pytest
import math
import string
import statistics
import os
import sys
from collections import Counter

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import (
    CryptoRandomEngine, EntropyAnalyzer, PasswordGenerator,
    CryptoVault, crypto_engine
)


class TestCryptoRandomEngine:
    """Tests for cryptographic randomness quality"""
    
    def test_random_bytes_length(self):
        """Random bytes output matches requested length"""
        for n in [1, 8, 16, 32, 64, 128, 256]:
            result = crypto_engine.get_random_bytes(n)
            assert len(result) == n, f"Expected {n} bytes, got {len(result)}"
    
    def test_random_bytes_uniqueness(self):
        """Random bytes should not repeat"""
        results = {crypto_engine.get_random_bytes(16) for _ in range(100)}
        assert len(results) == 100, "Unexpected collision in random bytes!"
    
    def test_random_int_bounds(self):
        """Random integers stay within specified bounds"""
        for _ in range(1000):
            val = crypto_engine.get_random_int(0, 100)
            assert 0 <= val <= 100, f"Value {val} out of bounds [0, 100]"
    
    def test_random_int_distribution(self):
        """Random integers should be roughly uniformly distributed"""
        N = 10000
        counts = Counter(crypto_engine.get_random_int(0, 9) for _ in range(N))
        
        # Each digit should appear ~1000 times ± statistical tolerance
        for digit in range(10):
            frequency = counts[digit] / N
            assert 0.08 <= frequency <= 0.12, \
                f"Non-uniform distribution at digit {digit}: {frequency:.4f}"
    
    def test_shuffle_preserves_elements(self):
        """Shuffle should not add, remove, or duplicate elements"""
        original = list(range(50))
        shuffled = crypto_engine.shuffle_secure(original)
        assert sorted(shuffled) == sorted(original)
    
    def test_shuffle_is_actually_shuffled(self):
        """Shuffled list should differ from original"""
        original = list(range(50))
        shuffled = crypto_engine.shuffle_secure(original)
        # Probability of being in original order is extremely low
        assert shuffled != original


class TestEntropyAnalyzer:
    """Tests for entropy calculation accuracy"""
    
    def test_shannon_entropy_empty(self):
        assert EntropyAnalyzer.shannon_entropy("") == 0.0
    
    def test_shannon_entropy_single_char(self):
        """Single repeated character has 0 entropy"""
        assert EntropyAnalyzer.shannon_entropy("aaaaaaaaaa") == 0.0
    
    def test_shannon_entropy_two_chars(self):
        """Equal distribution of 2 chars = 1 bit entropy"""
        result = EntropyAnalyzer.shannon_entropy("ababababab")
        assert abs(result - 1.0) < 0.01, f"Expected ~1.0, got {result}"
    
    def test_shannon_entropy_increases_with_diversity(self):
        """More character diversity = higher entropy"""
        low = EntropyAnalyzer.shannon_entropy("aaabbbccc")
        mid = EntropyAnalyzer.shannon_entropy("aabbccddee")
        high = EntropyAnalyzer.shannon_entropy("abcdefghij")
        assert low < mid < high, "Entropy should increase with diversity"
    
    def test_charset_entropy_full_complexity(self):
        """Password with all character classes should have high entropy"""
        password = "Tr0ub4dor&3xAmple#92Zk!"  # 24 chars, full complexity
        entropy = EntropyAnalyzer.charset_entropy(password)
        assert entropy > 100, f"Expected >100 bits, got {entropy:.1f}"
    
    def test_weak_password_detected(self):
        """Common passwords should receive low score"""
        analysis = EntropyAnalyzer.analyze_strength("password123")
        assert analysis['score'] <= 30, "Common password should score low"
        assert len(analysis['penalties']) > 0, "Should have penalties"
    
    def test_strong_password_analysis(self):
        """Well-formed password should score high"""
        password = PasswordGenerator.generate(length=32, strategy='random')
        analysis = EntropyAnalyzer.analyze_strength(password)
        assert analysis['effective_entropy'] > 80, "Strong password should have >80 bits entropy"
        assert analysis['score'] >= 70, "Strong password should score >=70"


class TestPasswordGenerator:
    """Tests for password generation correctness and security"""
    
    @pytest.mark.parametrize("length", [8, 12, 16, 24, 32, 64, 128])
    def test_password_length(self, length):
        """Generated password meets requested length"""
        password = PasswordGenerator.generate(length=length, strategy='random')
        assert len(password) >= length - 2, f"Password too short: {len(password)}"
    
    def test_password_uniqueness(self):
        """Each generated password should be unique"""
        passwords = {PasswordGenerator.generate(length=16) for _ in range(50)}
        assert len(passwords) == 50, "Generated duplicate passwords!"
    
    def test_lowercase_requirement(self):
        """When only lowercase requested, no uppercase or digits"""
        for _ in range(10):
            pw = PasswordGenerator.generate(
                length=20,
                use_uppercase=False,
                use_lowercase=True,
                use_digits=False,
                use_special=False
            )
            assert all(c in string.ascii_lowercase for c in pw), \
                f"Password contains non-lowercase: {pw}"
    
    def test_special_chars_included(self):
        """Special chars must appear when requested"""
        specials = set("!@#$%^&*()_+-=[]{}|;:',.<>?/~`")
        found = False
        for _ in range(20):
            pw = PasswordGenerator.generate(
                length=20,
                use_special=True
            )
            if any(c in specials for c in pw):
                found = True
                break
        assert found, "No special characters found in any generated passwords"
    
    def test_ambiguous_exclusion(self):
        """When exclude_ambiguous=True, ambiguous chars should not appear"""
        ambiguous = set('Il1O0o')
        for _ in range(50):
            pw = PasswordGenerator.generate(length=20, exclude_ambiguous=True)
            assert not any(c in ambiguous for c in pw), \
                f"Found ambiguous character in: {pw}"
    
    def test_all_strategies_produce_output(self):
        """All strategies should produce non-empty passwords"""
        for strategy in ['random', 'passphrase', 'pattern', 'hybrid']:
            pw = PasswordGenerator.generate(length=24, strategy=strategy)
            assert pw, f"Strategy '{strategy}' produced empty password"
            assert len(pw) >= 8, f"Strategy '{strategy}' too short: {pw}"


class TestCryptoVault:
    """Tests for encryption, hashing, and key derivation"""
    
    def test_aes_gcm_roundtrip(self):
        """AES-GCM encrypt then decrypt should return original"""
        key = os.urandom(32)
        plaintext = "super_secret_password_123!@#"
        
        encrypted = CryptoVault.encrypt_aes_gcm(plaintext, key)
        decrypted = CryptoVault.decrypt_aes_gcm(encrypted, key)
        
        assert decrypted == plaintext, "Decryption failed to return original"
    
    def test_aes_gcm_wrong_key_fails(self):
        """Decryption with wrong key should raise exception"""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        
        encrypted = CryptoVault.encrypt_aes_gcm("sensitive_data", key1)
        
        with pytest.raises(Exception):
            CryptoVault.decrypt_aes_gcm(encrypted, key2)
    
    def test_pbkdf2_deterministic(self):
        """Same password + salt should produce same key"""
        password = "my_master_password"
        salt = os.urandom(32)
        
        key1, _ = CryptoVault.derive_key_pbkdf2(password, salt=salt)
        key2, _ = CryptoVault.derive_key_pbkdf2(password, salt=salt)
        
        assert key1 == key2, "Deterministic derivation failed"
    
    def test_pbkdf2_different_salts(self):
        """Different salts should produce different keys"""
        password = "same_password"
        
        key1, _ = CryptoVault.derive_key_pbkdf2(password)
        key2, _ = CryptoVault.derive_key_pbkdf2(password)
        
        assert key1 != key2, "Different salts produced same key!"
    
    def test_hash_produces_salt(self):
        """Password hashing should produce unique salts"""
        hash1 = CryptoVault.hash_password("test")
        hash2 = CryptoVault.hash_password("test")
        
        assert hash1['salt'] != hash2['salt'], "Same salt reused"
        assert hash1['hash'] != hash2['hash'], "Same hash with different salts"


class TestStatisticalRandomness:
    """Statistical tests for randomness quality"""
    
    def test_monobit_frequency(self):
        """Bits should be ~50% ones, ~50% zeros"""
        random_bytes = crypto_engine.get_random_bytes(10000)
        
        total_bits = len(random_bytes) * 8
        one_bits = sum(bin(b).count('1') for b in random_bytes)
        
        ratio = one_bits / total_bits
        
        # Should be within 2% of 50%
        assert 0.48 <= ratio <= 0.52, \
            f"Monobit test failed: {ratio:.4f} (expected ~0.50)"
    
    def test_character_frequency_in_passwords(self):
        """Characters should be roughly uniformly distributed"""
        lowercase_counts = Counter()
        N = 1000
        
        for _ in range(N):
            pw = PasswordGenerator.generate(
                length=32,
                use_lowercase=True,
                use_uppercase=False,
                use_digits=False,
                use_special=False
            )
            for ch in pw:
                if ch in string.ascii_lowercase:
                    lowercase_counts[ch] += 1
        
        # Each letter should appear with similar frequency
        total = sum(lowercase_counts.values())
        frequencies = [lowercase_counts[ch] / total for ch in string.ascii_lowercase if ch in lowercase_counts]
        
        if frequencies:
            mean_freq = statistics.mean(frequencies)
            std_freq = statistics.stdev(frequencies)
            
            # Coefficient of variation should be reasonable
            cv = std_freq / mean_freq if mean_freq > 0 else 0
            assert cv < 0.20, f"Non-uniform character distribution (CV={cv:.4f})"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
