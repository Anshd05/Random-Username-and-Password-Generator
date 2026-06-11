#!/usr/bin/env python3
"""
Plugin Architecture for Password Generation Strategies
Allows extensible password generation with pluggable strategies.
"""

from abc import ABC, abstractmethod
from typing import Dict, Type


class PasswordStrategy(ABC):
    """Base class for all password generation strategies"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Strategy name"""
        ...
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description"""
        ...
    
    @property
    @abstractmethod
    def min_entropy_bits(self) -> float:
        """Minimum entropy this strategy guarantees"""
        ...
    
    @abstractmethod
    def generate(self, length: int, **kwargs) -> str:
        """Generate a password"""
        ...
    
    def validate(self, password: str) -> bool:
        """Validate generated password meets requirements"""
        from server import EntropyAnalyzer
        analysis = EntropyAnalyzer.analyze_strength(password)
        return analysis['effective_entropy'] >= self.min_entropy_bits


class MemorableStrategy(PasswordStrategy):
    """Generates highly memorable but secure passwords"""
    
    name = "memorable"
    description = "Memorable words with strategic substitutions"
    min_entropy_bits = 50.0
    
    MEMORABLE_PATTERNS = [
        "{Adj}{Sep}{Noun}{Num}{Sym}",
        "{Noun}{Adj}{Num}{Sym}",
        "{Adj}{Num}{Sep}{Noun}{Sym}",
    ]
    
    def generate(self, length: int, **kwargs) -> str:
        from server import crypto_engine, UsernameGenerator
        
        pattern = crypto_engine.get_random_choice(self.MEMORABLE_PATTERNS)
        adj = crypto_engine.get_random_choice(UsernameGenerator.ADJECTIVES)
        noun = crypto_engine.get_random_choice(UsernameGenerator.NOUNS)
        sep = crypto_engine.get_random_choice(['@', '#', '.', '_'])
        num = str(crypto_engine.get_random_int(10, 9999))
        sym = crypto_engine.get_random_choice('!@#$%^&*')
        
        result = (pattern
            .replace('{Adj}', adj)
            .replace('{Noun}', noun)
            .replace('{Sep}', sep)
            .replace('{Num}', num)
            .replace('{Sym}', sym))
        return result[:length] if len(result) > length else result


class PINStrategy(PasswordStrategy):
    """Cryptographically secure PIN/numeric codes"""
    
    name = "pin"
    description = "Secure numeric PIN"
    min_entropy_bits = 13.0  # 4 digits = log2(10^4)
    
    def generate(self, length: int = 6, **kwargs) -> str:
        from server import crypto_engine
        digits = [str(crypto_engine.get_random_int(0, 9)) for _ in range(length)]
        return ''.join(digits)


class StrategyRegistry:
    """Registry for password generation strategies (Plugin Pattern)"""
    
    _strategies: Dict[str, Type[PasswordStrategy]] = {}
    
    @classmethod
    def register(cls, strategy_class: Type[PasswordStrategy]):
        """Register a new strategy"""
        instance = strategy_class()
        cls._strategies[instance.name] = strategy_class
        return strategy_class  # Allow use as decorator
    
    @classmethod
    def get(cls, name: str) -> PasswordStrategy:
        """Get strategy instance by name"""
        if name not in cls._strategies:
            raise ValueError(f"Unknown strategy: {name}. "
                           f"Available: {list(cls._strategies.keys())}")
        return cls._strategies[name]()
    
    @classmethod
    def list_all(cls) -> list:
        """List all available strategies"""
        return [
            {
                "name": name,
                "description": cls._strategies[name]().description,
                "min_entropy": cls._strategies[name]().min_entropy_bits,
            }
            for name in cls._strategies
        ]


# Register built-in strategies
@StrategyRegistry.register
class _Memorable(MemorableStrategy):
    pass


@StrategyRegistry.register
class _PIN(PINStrategy):
    pass
