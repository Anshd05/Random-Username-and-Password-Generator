# 🚀 Local Development Setup Guide

## Prerequisites
- Python 3.11+
- pip (Python package manager)
- Git (optional)

## Installation

### 1. Clone or Download the Project
```bash
cd "Username & Password Generator"
```

### 2. Create Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Development Server
```bash
python server.py
```

The server will start on `http://localhost:5000`

## Testing

### Run Unit Tests
```bash
pytest tests/test_crypto.py -v
```

### Run with Coverage Report
```bash
pytest tests/test_crypto.py -v --cov=server --cov-report=html
```

### Run Specific Test Class
```bash
pytest tests/test_crypto.py::TestCryptoRandomEngine -v
```

## Verify Installation

### Check All Modules Load
```bash
python -c "from server import *; from plugins import *; from audit import *; from database import *; print('✅ All modules loaded successfully')"
```

### Test Crypto Functions
```python
python -c "
from server import PasswordGenerator, EntropyAnalyzer
pw = PasswordGenerator.generate(length=24)
strength = EntropyAnalyzer.analyze_strength(pw)
print(f'Generated: {pw}')
print(f'Entropy: {strength[\"effective_entropy\"]} bits')
print(f'Strength: {strength[\"strength\"]}')
"
```

## Project Structure

```
Username & Password Generator/
├── server.py              # Main application (Flask)
├── plugins.py             # Password strategy plugins
├── audit.py              # Security audit logging
├── database.py           # Credential storage (SQLAlchemy)
├── requirements.txt      # Python dependencies
├── templates/
│   └── index.html        # Web UI + PWA
├── static/
│   └── sw.js            # Service worker
├── tests/
│   └── test_crypto.py   # Test suite
├── manifest.json        # PWA configuration
├── Dockerfile          # Production image
├── docker-compose.yml  # Docker stack
├── nginx.conf         # Reverse proxy config
├── ENHANCEMENTS.md    # Feature documentation
└── SETUP.md          # This file
```

## Key Files & Their Purpose

| File | Purpose |
|------|---------|
| `server.py` | Core Flask application with all crypto operations |
| `plugins.py` | Plugin system for custom password strategies |
| `audit.py` | Event logging for security compliance |
| `database.py` | SQLAlchemy models for credential storage |
| `tests/test_crypto.py` | Comprehensive security test suite |
| `static/sw.js` | Service worker for offline PWA support |
| `templates/index.html` | Web interface + client-side crypto |

## Common Tasks

### Generate a Password Programmatically
```python
from server import PasswordGenerator, EntropyAnalyzer

password = PasswordGenerator.generate(
    length=32,
    strategy='random',
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    use_special=True
)

strength = EntropyAnalyzer.analyze_strength(password)
print(f"Password: {password}")
print(f"Entropy: {strength['effective_entropy']} bits")
print(f"Strength: {strength['strength']}")
```

### Register a Custom Strategy
```python
from plugins import PasswordStrategy, StrategyRegistry

@StrategyRegistry.register
class MyCustomStrategy(PasswordStrategy):
    name = "my_custom"
    description = "My custom password strategy"
    min_entropy_bits = 70.0
    
    def generate(self, length: int, **kwargs) -> str:
        # Your implementation here
        return "generated_password"

# Use it
strategy = StrategyRegistry.get("my_custom")
password = strategy.generate(length=24)
```

### Log Security Events
```python
from audit import audit_logger, AuditEvent, AuditEventType

event = AuditEvent(
    event_type=AuditEventType.CREDENTIAL_GENERATED,
    entropy_bits=95.5,
    strength_level="EXCELLENT",
    password_length=24
)

audit_logger.log(event)
```

### Save Credential to Database
```python
from database import credential_repo

credential_data = {
    'username': 'john_doe',
    'password_hash': {'hash': '...', 'salt': '...', 'algorithm': 'sha3_512'},
    'strength': {'effective_entropy': 95.5, 'strength': 'EXCELLENT', ...},
    'strategy': 'random'
}

saved_cred = credential_repo.save(credential_data)
print(f"Saved with ID: {saved_cred.id}")
```

## Environment Variables

### Development
```bash
FLASK_ENV=development
DEBUG=True
```

### Production
```bash
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///credentials.db
```

## Docker Development

### Build Image
```bash
docker build -t cryptogen:dev .
```

### Run Container
```bash
docker run -p 5000:5000 -e FLASK_ENV=development cryptogen:dev
```

### Full Stack (with Nginx)
```bash
docker-compose up -d
```

Access at `https://localhost` (self-signed cert warning is normal in dev)

## Troubleshooting

### Module Import Errors
```bash
# Verify all modules compile
python -m py_compile server.py plugins.py audit.py database.py
```

### Port Already in Use
```bash
# Use different port
python -c "from server import app; app.run(port=8080)"
```

### Database Issues
```bash
# Reset database
rm credentials.db
# Server will recreate on startup
```

### Service Worker Issues
- Use HTTPS or localhost for SW to register
- Check browser DevTools > Application > Service Workers
- Look at Console for error messages

## Performance Testing

### Generate 100 Passwords
```bash
time python -c "
from server import PasswordGenerator
for _ in range(100):
    PasswordGenerator.generate(length=24)
print('Done')
"
```

### Generate 1000 Passwords (Batch)
```bash
time python -c "
from server import PasswordGenerator
passwords = [PasswordGenerator.generate(length=24) for _ in range(1000)]
print(f'Generated {len(passwords)} passwords')
"
```

## Next Steps

1. **Review Security Features:** Check [ENHANCEMENTS.md](ENHANCEMENTS.md)
2. **Run Tests:** `pytest tests/test_crypto.py -v`
3. **Explore Plugins:** Create custom password strategies
4. **Deploy:** Use Docker for production (`docker-compose up -d`)
5. **Monitor:** Check `audit.log` for security events

## Support & Documentation

- **API Docs:** See `ENHANCEMENTS.md` for API endpoints
- **Tests:** See `tests/test_crypto.py` for usage examples
- **Code:** Well-documented with docstrings throughout

---

Happy generating! 🔐
