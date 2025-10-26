"""
OWASP A02:2021 - Cryptographic Failures
==========================================

Cryptographic failures relate to failures related to cryptography (or lack thereof),
which often lead to exposure of sensitive data. This includes passwords, credit card
numbers, health records, personal information, and business secrets.

Common vulnerabilities:
- Storing sensitive data in plaintext
- Using weak or deprecated cryptographic algorithms
- Improper key management
- Missing encryption in transit
- Weak password hashing
- Predictable tokens or keys
"""

from flask import Flask, request, jsonify
import hashlib
import sqlite3
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import bcrypt
import secrets

app = Flask(__name__)

# ============================================================================
# VULNERABLE CODE EXAMPLES
# ============================================================================

# Example 1: Plaintext Password Storage
@app.route('/api/register_vulnerable', methods=['POST'])
def register_plaintext_password():
    """
    VULNERABILITY: Storing passwords in plaintext
    
    Attack: Database breach exposes all passwords
    Impact: Account takeover, credential stuffing
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')  # Plaintext!
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Storing password in plaintext - NEVER DO THIS!
    cursor.execute("""
        INSERT INTO users (username, password, email)
        VALUES (?, ?, ?)
    """, (username, password, data.get('email')))
    conn.commit()
    
    return jsonify({'message': 'User registered'})


# Example 2: Weak Hashing Algorithm (MD5)
@app.route('/api/register_weak_hash', methods=['POST'])
def register_weak_hash():
    """
    VULNERABILITY: Using MD5 for password hashing
    
    Attack: MD5 is broken, easily cracked with rainbow tables
    Impact: Passwords recovered in seconds
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # MD5 is cryptographically broken - DO NOT USE!
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, password_hash)
        VALUES (?, ?)
    """, (username, password_hash))
    conn.commit()
    
    return jsonify({'message': 'User registered'})


# Example 3: Hardcoded Encryption Key
class VulnerableEncryption:
    """
    VULNERABILITY: Hardcoded encryption key in source code
    
    Attack: Key visible in source code or decompiled binary
    Impact: All encrypted data can be decrypted
    """
    # HARDCODED KEY - Never do this!
    KEY = b'hardcoded-32-byte-key-never-use'
    
    @staticmethod
    def encrypt_sensitive_data(data):
        """Encrypt with hardcoded key"""
        from cryptography.fernet import Fernet
        cipher = Fernet(base64.urlsafe_b64encode(VulnerableEncryption.KEY))
        return cipher.encrypt(data.encode())
    
    @staticmethod
    def decrypt_sensitive_data(encrypted_data):
        """Decrypt with hardcoded key"""
        from cryptography.fernet import Fernet
        cipher = Fernet(base64.urlsafe_b64encode(VulnerableEncryption.KEY))
        return cipher.decrypt(encrypted_data).decode()


# Example 4: Storing Credit Cards in Plaintext
@app.route('/api/payment/save_card_vulnerable', methods=['POST'])
def save_credit_card_vulnerable():
    """
    VULNERABILITY: Storing credit card numbers unencrypted
    
    Attack: Database breach exposes all credit cards
    Impact: Financial fraud, PCI-DSS violation, lawsuits
    """
    data = request.get_json()
    user_id = data.get('user_id')
    card_number = data.get('card_number')  # Full card number!
    cvv = data.get('cvv')  # CVV should NEVER be stored!
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    
    # Storing sensitive payment data unencrypted
    cursor.execute("""
        INSERT INTO payment_methods (user_id, card_number, cvv, expiry)
        VALUES (?, ?, ?, ?)
    """, (user_id, card_number, cvv, data.get('expiry')))
    conn.commit()
    
    return jsonify({'message': 'Card saved'})


# Example 5: Weak Random Token Generation
def generate_reset_token_weak():
    """
    VULNERABILITY: Predictable token generation
    
    Attack: Attacker can guess/enumerate tokens
    Impact: Account takeover via password reset
    """
    import time
    import random
    
    # Using time-based seed - predictable!
    random.seed(int(time.time()))
    token = random.randint(100000, 999999)  # 6-digit token
    
    return str(token)


# Example 6: SHA1 for Password Hashing (without salt)
def hash_password_sha1_no_salt(password):
    """
    VULNERABILITY: SHA1 without salt
    
    Attack: Rainbow table attacks
    Impact: Passwords cracked quickly
    """
    # SHA1 is deprecated and no salt used
    return hashlib.sha1(password.encode()).hexdigest()


# ============================================================================
# SECURE CODE EXAMPLES
# ============================================================================

# Example 1: SECURE - Proper Password Hashing with bcrypt
@app.route('/api/register_secure', methods=['POST'])
def register_secure():
    """
    SECURE: Using bcrypt for password hashing
    
    Defense: bcrypt is slow (designed to be), includes salt automatically
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Validate password strength
    if len(password) < 12:
        return jsonify({'error': 'Password must be at least 12 characters'}), 400
    
    # Hash password with bcrypt (includes salt automatically)
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, password_hash)
        VALUES (?, ?)
    """, (username, password_hash))
    conn.commit()
    
    return jsonify({'message': 'User registered securely'}), 201


@app.route('/api/login_secure', methods=['POST'])
def login_secure():
    """
    SECURE: Verifying password with bcrypt
    
    Defense: Constant-time comparison, resistant to timing attacks
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode(), user[0]):
        return jsonify({'message': 'Login successful'})
    
    # Generic error message (don't reveal if username exists)
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 2: SECURE - Proper Encryption Key Management
class SecureEncryption:
    """
    SECURE: Load encryption key from environment or key management service
    
    Defense: Keys stored securely, rotated regularly, never in source code
    """
    
    @staticmethod
    def get_encryption_key():
        """Get key from environment or KMS"""
        key = os.environ.get('ENCRYPTION_KEY')
        
        if not key:
            # In production, use AWS KMS, Azure Key Vault, etc.
            raise ValueError("ENCRYPTION_KEY not set in environment")
        
        return key.encode()
    
    @staticmethod
    def derive_key_from_password(password, salt=None):
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # High iteration count
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_data(data, key):
        """Encrypt data with Fernet (symmetric encryption)"""
        cipher = Fernet(key)
        return cipher.encrypt(data.encode())
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Decrypt data"""
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_data).decode()


# Example 3: SECURE - Storing Credit Cards (PCI-DSS Compliant)
@app.route('/api/payment/save_card_secure', methods=['POST'])
def save_credit_card_secure():
    """
    SECURE: Tokenize credit cards, don't store sensitive data
    
    Defense: Use payment gateway tokenization (Stripe, PayPal)
    """
    data = request.get_json()
    user_id = data.get('user_id')
    
    # In production, use Stripe/PayPal tokenization
    # This is a simplified example
    card_number = data.get('card_number')
    
    # Extract last 4 digits only
    last_four = card_number[-4:]
    
    # In real implementation, send full card to payment gateway
    # and receive a token back
    card_token = tokenize_card_with_gateway(card_number)
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    
    # Store only token and last 4 digits
    # NEVER store CVV - PCI-DSS violation!
    cursor.execute("""
        INSERT INTO payment_methods (user_id, card_token, last_four, card_type)
        VALUES (?, ?, ?, ?)
    """, (user_id, card_token, last_four, detect_card_type(card_number)))
    conn.commit()
    
    return jsonify({
        'message': 'Card saved securely',
        'last_four': last_four
    })


def tokenize_card_with_gateway(card_number):
    """
    Use payment gateway's tokenization service
    Example with Stripe:
    
    import stripe
    stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
    
    token = stripe.Token.create(
        card={
            "number": card_number,
            "exp_month": exp_month,
            "exp_year": exp_year,
            "cvc": cvc,
        },
    )
    return token.id
    """
    # Placeholder - use real payment gateway in production
    return f"tok_{secrets.token_urlsafe(24)}"


def detect_card_type(card_number):
    """Detect card type from number"""
    first_digit = card_number[0]
    if first_digit == '4':
        return 'Visa'
    elif first_digit == '5':
        return 'Mastercard'
    elif first_digit == '3':
        return 'Amex'
    return 'Unknown'


# Example 4: SECURE - Cryptographically Secure Token Generation
def generate_reset_token_secure():
    """
    SECURE: Using secrets module for token generation
    
    Defense: Cryptographically secure random generation
    """
    # Generate 32-byte token (256 bits)
    token = secrets.token_urlsafe(32)
    return token


def generate_session_id_secure():
    """
    SECURE: Generate secure session ID
    
    Defense: High entropy, unpredictable
    """
    return secrets.token_hex(32)  # 64 characters hex


# Example 5: SECURE - Encrypting Sensitive Data at Rest
class SecureDatabaseEncryption:
    """
    SECURE: Encrypt sensitive fields before storing in database
    
    Defense: Field-level encryption for PII
    """
    
    def __init__(self):
        key = os.environ.get('DB_ENCRYPTION_KEY')
        if not key:
            raise ValueError("DB_ENCRYPTION_KEY not set")
        self.cipher = Fernet(key.encode())
    
    def encrypt_ssn(self, ssn):
        """Encrypt SSN before storing"""
        return self.cipher.encrypt(ssn.encode())
    
    def decrypt_ssn(self, encrypted_ssn):
        """Decrypt SSN when needed"""
        return self.cipher.decrypt(encrypted_ssn).decode()
    
    def store_user_with_encryption(self, username, ssn, email):
        """Store user with encrypted SSN"""
        encrypted_ssn = self.encrypt_ssn(ssn)
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, ssn_encrypted, email)
            VALUES (?, ?, ?)
        """, (username, encrypted_ssn, email))
        conn.commit()


# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
CRYPTOGRAPHIC BEST PRACTICES:

1. Password Storage
   ✅ Use bcrypt, scrypt, or Argon2 (never MD5/SHA1)
   ✅ Use high work factor/cost (bcrypt rounds=12+)
   ✅ Salt is included automatically with bcrypt
   ✅ Use constant-time comparison

2. Encryption
   ✅ Use strong algorithms (AES-256, RSA-2048+)
   ✅ Never hardcode encryption keys
   ✅ Use authenticated encryption (GCM mode)
   ✅ Rotate keys regularly
   ✅ Use key management services (AWS KMS, Azure Key Vault)

3. Sensitive Data
   ✅ Encrypt data at rest and in transit
   ✅ Use TLS 1.3 for data in transit
   ✅ Don't log sensitive data
   ✅ Minimize data retention
   ✅ Use tokenization for payment cards

4. Random Values
   ✅ Use secrets module (not random)
   ✅ Generate high-entropy tokens (32+ bytes)
   ✅ Use UUIDs for identifiers

5. Key Management
   ✅ Store keys separately from data
   ✅ Use hardware security modules (HSM)
   ✅ Implement key rotation
   ✅ Use different keys for different purposes

CODE CHECKLIST:

✅ Never store passwords in plaintext
✅ Use bcrypt/scrypt/Argon2 for passwords
✅ Never use MD5/SHA1 for passwords
✅ Load keys from environment or KMS
✅ Never hardcode secrets in source code
✅ Use TLS for all network communication
✅ Encrypt sensitive data at rest
✅ Use secrets module for tokens
✅ Implement proper key rotation
✅ Follow PCI-DSS for payment data
✅ Use authenticated encryption (AES-GCM)
✅ Validate input before encryption
✅ Log encryption/decryption failures (not keys!)
✅ Use strong random number generation
"""

# ============================================================================
# REAL-WORLD EXAMPLES
# ============================================================================

"""
REAL-WORLD CRYPTOGRAPHIC FAILURES:

1. Adobe (2013)
   - 153 million accounts compromised
   - Passwords encrypted with ECB mode (weak)
   - Same password = same ciphertext
   - Password hints stored unencrypted

2. LinkedIn (2012)
   - 117 million passwords hashed with SHA1
   - No salt used
   - Passwords cracked using rainbow tables
   - Led to massive credential stuffing attacks

3. Dropbox (2012)
   - 68 million accounts exposed
   - Passwords hashed with SHA1 (unsalted)
   - Employee reused passwords across sites

4. Yahoo (2013-2014)
   - 3 billion accounts compromised
   - Weak MD5 hashing
   - Security questions compromised

5. Uber (2016)
   - AWS keys stored in GitHub repository
   - Led to breach of 57 million users
   - $148 million settlement

KEY LESSONS:
- Use modern password hashing (bcrypt, Argon2)
- Never store keys in source code
- Encrypt sensitive data at rest
- Use proper key management
- Regular security audits
"""

# ============================================================================
# TESTING & VALIDATION
# ============================================================================

def test_password_hashing():
    """Test password hashing security"""
    print("\n=== Testing Password Hashing ===")
    
    password = "SecurePassword123!"
    
    # Vulnerable: MD5
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    print(f"❌ MD5: {md5_hash}")
    print("   Crackable in seconds with rainbow tables")
    
    # Secure: bcrypt
    bcrypt_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    print(f"✅ bcrypt: {bcrypt_hash}")
    print("   Includes salt, slow by design, resistant to attacks")


def test_token_generation():
    """Test token generation security"""
    print("\n=== Testing Token Generation ===")
    
    import random
    import time
    
    # Vulnerable: Predictable
    random.seed(int(time.time()))
    weak_token = random.randint(100000, 999999)
    print(f"❌ Weak token: {weak_token}")
    print("   Predictable, can be brute-forced")
    
    # Secure: Cryptographically secure
    secure_token = secrets.token_urlsafe(32)
    print(f"✅ Secure token: {secure_token}")
    print("   High entropy, unpredictable")


if __name__ == '__main__':
    print("OWASP A02:2021 - Cryptographic Failures Examples")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- Weak password hashing (MD5, SHA1)")
    print("- Hardcoded encryption keys")
    print("- Plaintext sensitive data storage")
    print("- Secure alternatives with bcrypt, Fernet, secrets")
    
    # Run tests
    test_password_hashing()
    test_token_generation()
    
    print("\n" + "=" * 60)
    print("Key Takeaway: Use bcrypt for passwords, encrypt sensitive data,")
    print("never hardcode keys, use secrets module for tokens!")

