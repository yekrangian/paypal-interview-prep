"""
OWASP A07:2021 - Identification and Authentication Failures
===========================================================

Confirmation of the user's identity, authentication, and session management 
is critical to protect against authentication-related attacks. Failures include
permitting brute force attacks, allowing weak passwords, exposing session IDs.

Common vulnerabilities:
- Weak password policies
- Credential stuffing
- Session fixation
- Missing MFA/2FA
- Insecure session management
- Username enumeration
- Password reset flaws
"""

from flask import Flask, request, jsonify, session
import sqlite3
import hashlib
import secrets
import bcrypt
from datetime import datetime, timedelta
import time

app = Flask(__name__)
app.secret_key = 'change-this-in-production'

# ============================================================================
# VULNERABLE CODE EXAMPLES
# ============================================================================

# Example 1: Weak Password Policy
@app.route('/api/register_weak_password', methods=['POST'])
def register_weak_password():
    """
    VULNERABILITY: No password strength requirements
    
    Attack: Users choose weak passwords like "123456", "password"
    Impact: Easy brute force, credential stuffing attacks
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')  # No validation!
    
    # Accepts any password, even "123"
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    cursor.execute("""
        INSERT INTO users (username, password_hash)
        VALUES (?, ?)
    """, (username, password_hash))
    conn.commit()
    
    return jsonify({'message': 'User registered'})


# Example 2: No Rate Limiting - Brute Force Vulnerable
login_attempts = {}  # In-memory tracking (not persistent!)

@app.route('/api/login_no_rate_limit', methods=['POST'])
def login_no_rate_limit():
    """
    VULNERABILITY: No rate limiting on login attempts
    
    Attack: Attacker can try thousands of passwords per second
    Impact: Account takeover via brute force
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode(), user[0]):
        session['user'] = username
        return jsonify({'message': 'Login successful'})
    
    # No delay, no rate limiting - try again immediately!
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 3: Username Enumeration
@app.route('/api/login_enumeration', methods=['POST'])
def login_enumeration():
    """
    VULNERABILITY: Different error messages reveal if username exists
    
    Attack: Attacker can enumerate valid usernames
    Impact: Targeted attacks on known accounts
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        # Reveals username doesn't exist!
        return jsonify({'error': 'Username not found'}), 404
    
    if not bcrypt.checkpw(password.encode(), user[0]):
        # Reveals username exists but password is wrong!
        return jsonify({'error': 'Incorrect password'}), 401
    
    return jsonify({'message': 'Login successful'})


# Example 4: Insecure Session Management
@app.route('/api/login_weak_session', methods=['POST'])
def login_weak_session():
    """
    VULNERABILITY: Predictable session IDs, no expiration
    
    Attack: Session hijacking, session fixation
    Impact: Account takeover
    """
    data = request.get_json()
    username = data.get('username')
    
    # Predictable session ID based on username!
    session_id = hashlib.md5(username.encode()).hexdigest()
    
    # No expiration time set
    session['session_id'] = session_id
    session['username'] = username
    # session.permanent = False  # Never expires in this session!
    
    return jsonify({
        'message': 'Login successful',
        'session_id': session_id  # Exposing session ID in response!
    })


# Example 5: Insecure Password Reset
reset_tokens = {}  # Global dict (vulnerable!)

@app.route('/api/password/reset_request_vulnerable', methods=['POST'])
def password_reset_request_vulnerable():
    """
    VULNERABILITY: Predictable reset tokens
    
    Attack: Attacker can guess reset tokens
    Impact: Account takeover
    """
    data = request.get_json()
    email = data.get('email')
    
    # Predictable 6-digit token
    import random
    token = str(random.randint(100000, 999999))
    
    reset_tokens[email] = token
    
    # In real app, send email here
    print(f"Reset token for {email}: {token}")
    
    return jsonify({'message': 'Reset email sent'})


@app.route('/api/password/reset_vulnerable', methods=['POST'])
def password_reset_vulnerable():
    """
    VULNERABILITY: No rate limiting, tokens don't expire
    
    Attack: Brute force reset tokens
    Impact: Account takeover
    """
    data = request.get_json()
    email = data.get('email')
    token = data.get('token')
    new_password = data.get('new_password')
    
    # No rate limiting - can try all 1,000,000 tokens!
    if reset_tokens.get(email) == token:
        # Update password
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", 
                      (password_hash, email))
        conn.commit()
        
        return jsonify({'message': 'Password reset successful'})
    
    return jsonify({'error': 'Invalid token'}), 401


# Example 6: No Multi-Factor Authentication (MFA)
@app.route('/api/login_no_mfa', methods=['POST'])
def login_no_mfa():
    """
    VULNERABILITY: No MFA for sensitive accounts
    
    Attack: Compromised password = full account access
    Impact: Account takeover even with strong passwords
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT password_hash, is_admin 
        FROM users 
        WHERE username = ?
    """, (username,))
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode(), user[0]):
        # Admin account with no MFA requirement!
        session['username'] = username
        session['is_admin'] = user[1]
        
        return jsonify({
            'message': 'Login successful',
            'is_admin': user[1]
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401


# ============================================================================
# SECURE CODE EXAMPLES
# ============================================================================

# Example 1: SECURE - Strong Password Policy
def validate_password_strength(password):
    """
    SECURE: Enforce strong password requirements
    
    Defense: Multiple criteria for password strength
    """
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain number")
    
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        errors.append("Password must contain special character")
    
    # Check against common passwords
    common_passwords = ['password', '123456', 'password123', 'qwerty']
    if password.lower() in common_passwords:
        errors.append("Password is too common")
    
    return errors


@app.route('/api/register_secure', methods=['POST'])
def register_secure():
    """
    SECURE: Strong password policy enforced
    
    Defense: Multiple validation criteria
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Validate password strength
    errors = validate_password_strength(password)
    if errors:
        return jsonify({'errors': errors}), 400
    
    # Check password hasn't been breached (haveibeenpwned API)
    # if check_password_breach(password):
    #     return jsonify({'error': 'Password found in breach database'}), 400
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    
    cursor.execute("""
        INSERT INTO users (username, password_hash, created_at)
        VALUES (?, ?, ?)
    """, (username, password_hash, datetime.now()))
    conn.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201


# Example 2: SECURE - Rate Limiting with Exponential Backoff
class RateLimiter:
    """
    SECURE: Implement rate limiting with exponential backoff
    
    Defense: Slow down brute force attacks
    """
    def __init__(self):
        self.attempts = {}  # {identifier: [(timestamp, count)]}
    
    def is_allowed(self, identifier, max_attempts=5, window_minutes=15):
        """Check if request is allowed"""
        now = datetime.now()
        
        if identifier not in self.attempts:
            self.attempts[identifier] = []
        
        # Clean old attempts outside window
        self.attempts[identifier] = [
            (ts, count) for ts, count in self.attempts[identifier]
            if now - ts < timedelta(minutes=window_minutes)
        ]
        
        # Count recent attempts
        total_attempts = sum(count for ts, count in self.attempts[identifier])
        
        if total_attempts >= max_attempts:
            return False, self.get_lockout_duration(total_attempts)
        
        return True, 0
    
    def record_attempt(self, identifier):
        """Record failed attempt"""
        now = datetime.now()
        if identifier not in self.attempts:
            self.attempts[identifier] = []
        self.attempts[identifier].append((now, 1))
    
    def get_lockout_duration(self, attempts):
        """Calculate exponential backoff"""
        if attempts < 5:
            return 0
        elif attempts < 10:
            return 60  # 1 minute
        elif attempts < 20:
            return 300  # 5 minutes
        else:
            return 3600  # 1 hour


rate_limiter = RateLimiter()

@app.route('/api/login_rate_limited', methods=['POST'])
def login_rate_limited():
    """
    SECURE: Rate limiting prevents brute force
    
    Defense: Exponential backoff after failed attempts
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Use IP + username as identifier
    identifier = f"{request.remote_addr}:{username}"
    
    # Check rate limit
    allowed, lockout_duration = rate_limiter.is_allowed(identifier)
    if not allowed:
        return jsonify({
            'error': 'Too many failed attempts',
            'retry_after': lockout_duration
        }), 429
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    # Constant-time comparison to prevent timing attacks
    if user and bcrypt.checkpw(password.encode(), user[0]):
        # Clear failed attempts on success
        rate_limiter.attempts.pop(identifier, None)
        session['user'] = username
        return jsonify({'message': 'Login successful'})
    
    # Record failed attempt
    rate_limiter.record_attempt(identifier)
    
    # Generic error message (prevent enumeration)
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 3: SECURE - Prevent Username Enumeration
@app.route('/api/login_no_enumeration', methods=['POST'])
def login_no_enumeration():
    """
    SECURE: Generic error messages, constant-time response
    
    Defense: Cannot determine if username exists
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    # Always hash password even if user doesn't exist (timing attack prevention)
    if user:
        password_hash = user[0]
    else:
        # Dummy hash to maintain consistent timing
        password_hash = bcrypt.hashpw(b'dummy', bcrypt.gensalt())
    
    # Always check password (constant time)
    is_valid = bcrypt.checkpw(password.encode(), password_hash) and user is not None
    
    if is_valid:
        session['user'] = username
        return jsonify({'message': 'Login successful'})
    
    # Generic error message - doesn't reveal if username exists
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 4: SECURE - Session Management
@app.route('/api/login_secure_session', methods=['POST'])
def login_secure_session():
    """
    SECURE: Cryptographically secure session IDs with expiration
    
    Defense: Unpredictable sessions, automatic expiration
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode(), user[0]):
        # Regenerate session ID on login (prevent session fixation)
        session.clear()
        
        # Set secure session parameters
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=30)
        
        # Store user info
        session['user'] = username
        session['login_time'] = datetime.now().isoformat()
        session['ip'] = request.remote_addr  # Bind session to IP
        
        # Generate CSRF token
        session['csrf_token'] = secrets.token_urlsafe(32)
        
        return jsonify({
            'message': 'Login successful',
            'expires_in': 1800  # 30 minutes in seconds
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/logout_secure', methods=['POST'])
def logout_secure():
    """
    SECURE: Proper session invalidation
    
    Defense: Clear session data on logout
    """
    session.clear()  # Completely clear session
    return jsonify({'message': 'Logged out successfully'})


# Example 5: SECURE - Password Reset with Secure Tokens
class PasswordResetManager:
    """
    SECURE: Secure password reset token management
    
    Defense: Cryptographically secure tokens with expiration
    """
    def __init__(self):
        self.tokens = {}  # In production, use Redis or database
    
    def create_reset_token(self, email):
        """Generate cryptographically secure token"""
        token = secrets.token_urlsafe(32)  # 256-bit token
        
        self.tokens[token] = {
            'email': email,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=1),
            'used': False
        }
        
        return token
    
    def validate_token(self, token, email):
        """Validate token and check expiration"""
        if token not in self.tokens:
            return False
        
        token_data = self.tokens[token]
        
        # Check if already used
        if token_data['used']:
            return False
        
        # Check expiration
        if datetime.now() > token_data['expires_at']:
            return False
        
        # Check email matches
        if token_data['email'] != email:
            return False
        
        return True
    
    def mark_used(self, token):
        """Mark token as used (single-use only)"""
        if token in self.tokens:
            self.tokens[token]['used'] = True


reset_manager = PasswordResetManager()

@app.route('/api/password/reset_request_secure', methods=['POST'])
def password_reset_request_secure():
    """
    SECURE: Generate secure reset token
    
    Defense: Cryptographically secure, time-limited, single-use
    """
    data = request.get_json()
    email = data.get('email')
    
    # Always return success (prevent email enumeration)
    # In production, only send email if account exists
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    if user:
        token = reset_manager.create_reset_token(email)
        
        # Send email with reset link
        # send_reset_email(email, token)
        print(f"Reset link: /reset-password?token={token}")
    
    # Always return same message (prevent enumeration)
    return jsonify({
        'message': 'If account exists, reset email sent'
    })


@app.route('/api/password/reset_secure', methods=['POST'])
def password_reset_secure():
    """
    SECURE: Validate token before password reset
    
    Defense: Single-use tokens, rate limiting, strong password requirements
    """
    data = request.get_json()
    email = data.get('email')
    token = data.get('token')
    new_password = data.get('new_password')
    
    # Rate limit reset attempts
    identifier = f"reset:{request.remote_addr}"
    allowed, lockout = rate_limiter.is_allowed(identifier, max_attempts=3)
    if not allowed:
        return jsonify({'error': 'Too many attempts'}), 429
    
    # Validate token
    if not reset_manager.validate_token(token, email):
        rate_limiter.record_attempt(identifier)
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    # Validate new password strength
    errors = validate_password_strength(new_password)
    if errors:
        return jsonify({'errors': errors}), 400
    
    # Update password
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=12))
    cursor.execute("""
        UPDATE users 
        SET password_hash = ?, password_changed_at = ? 
        WHERE email = ?
    """, (password_hash, datetime.now(), email))
    conn.commit()
    
    # Mark token as used
    reset_manager.mark_used(token)
    
    # Invalidate all existing sessions
    # invalidate_user_sessions(email)
    
    return jsonify({'message': 'Password reset successful'})


# Example 6: SECURE - Multi-Factor Authentication (MFA)
class MFAManager:
    """
    SECURE: Multi-factor authentication with TOTP
    
    Defense: Additional layer beyond passwords
    """
    def __init__(self):
        self.pending_mfa = {}  # {session_id: user_data}
    
    def require_mfa(self, username):
        """Check if user requires MFA"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT is_admin, mfa_enabled 
            FROM users 
            WHERE username = ?
        """, (username,))
        user = cursor.fetchone()
        
        # Require MFA for admins or if user enabled it
        return user and (user[0] or user[1])
    
    def generate_mfa_code(self, username):
        """Generate 6-digit MFA code"""
        # In production, use TOTP (Time-based One-Time Password)
        # import pyotp
        # secret = get_user_mfa_secret(username)
        # totp = pyotp.TOTP(secret)
        # return totp.now()
        
        # For demo: random 6-digit code
        code = secrets.randbelow(900000) + 100000
        return str(code)
    
    def verify_mfa_code(self, username, code):
        """Verify MFA code"""
        # In production, verify TOTP code
        # import pyotp
        # secret = get_user_mfa_secret(username)
        # totp = pyotp.TOTP(secret)
        # return totp.verify(code, valid_window=1)
        
        # For demo: check stored code
        return True  # Placeholder


mfa_manager = MFAManager()

@app.route('/api/login_with_mfa', methods=['POST'])
def login_with_mfa():
    """
    SECURE: Multi-factor authentication for sensitive accounts
    
    Defense: Two factors required for access
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user or not bcrypt.checkpw(password.encode(), user[0]):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if MFA required
    if mfa_manager.require_mfa(username):
        # Generate MFA code
        mfa_code = mfa_manager.generate_mfa_code(username)
        
        # Store in pending MFA
        temp_session_id = secrets.token_urlsafe(16)
        mfa_manager.pending_mfa[temp_session_id] = {
            'username': username,
            'mfa_code': mfa_code,
            'expires': datetime.now() + timedelta(minutes=5)
        }
        
        # Send MFA code via SMS/email
        print(f"MFA code for {username}: {mfa_code}")
        
        return jsonify({
            'mfa_required': True,
            'temp_session': temp_session_id,
            'message': 'MFA code sent'
        })
    
    # No MFA required - complete login
    session['user'] = username
    return jsonify({'message': 'Login successful'})


@app.route('/api/login/verify_mfa', methods=['POST'])
def verify_mfa():
    """
    SECURE: Verify MFA code
    
    Defense: Complete two-factor authentication
    """
    data = request.get_json()
    temp_session = data.get('temp_session')
    mfa_code = data.get('mfa_code')
    
    # Validate temp session
    if temp_session not in mfa_manager.pending_mfa:
        return jsonify({'error': 'Invalid session'}), 401
    
    pending = mfa_manager.pending_mfa[temp_session]
    
    # Check expiration
    if datetime.now() > pending['expires']:
        del mfa_manager.pending_mfa[temp_session]
        return jsonify({'error': 'Code expired'}), 401
    
    # Verify MFA code
    if mfa_code != pending['mfa_code']:
        return jsonify({'error': 'Invalid code'}), 401
    
    # MFA successful - complete login
    session['user'] = pending['username']
    session['mfa_verified'] = True
    
    # Clean up pending MFA
    del mfa_manager.pending_mfa[temp_session]
    
    return jsonify({'message': 'Login successful'})


# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
AUTHENTICATION BEST PRACTICES:

Password Policy:
✅ Minimum 12 characters
✅ Require uppercase, lowercase, numbers, special chars
✅ Check against breached password database (haveibeenpwned)
✅ Don't allow common passwords
✅ Enforce password expiration for sensitive accounts
✅ Password history (prevent reuse)

Account Security:
✅ Rate limiting on login (exponential backoff)
✅ Account lockout after repeated failures
✅ Generic error messages (prevent enumeration)
✅ Log all authentication events
✅ Monitor for credential stuffing patterns
✅ Implement CAPTCHA after failed attempts

Session Management:
✅ Cryptographically secure session IDs
✅ Regenerate session ID on login
✅ Set session expiration (30 minutes default)
✅ Bind session to IP address
✅ Implement proper logout (clear session)
✅ Use httpOnly and secure cookies

Multi-Factor Authentication:
✅ Require MFA for admin accounts
✅ Offer MFA for all users
✅ Use TOTP (Time-based One-Time Password)
✅ Backup codes for MFA recovery
✅ Don't reuse MFA codes

Password Reset:
✅ Cryptographically secure tokens (32+ bytes)
✅ Single-use tokens
✅ Short expiration (1 hour)
✅ Rate limit reset attempts
✅ Don't reveal if email exists
✅ Invalidate old sessions after reset

CODE CHECKLIST:

✅ Strong password requirements enforced
✅ Passwords hashed with bcrypt (12+ rounds)
✅ Rate limiting on login endpoints
✅ Generic error messages (no enumeration)
✅ Secure session management (regenerate on login)
✅ Session expiration configured
✅ MFA for admin/sensitive accounts
✅ Secure password reset tokens
✅ Account lockout mechanism
✅ Constant-time password comparison
✅ Log authentication events
✅ Monitor for brute force attacks
"""

# ============================================================================
# REAL-WORLD EXAMPLES
# ============================================================================

"""
REAL-WORLD AUTHENTICATION FAILURES:

1. Dropbox (2012)
   - No rate limiting on password resets
   - 68 million accounts compromised
   - Weak hashing (SHA1, unsalted)
   - Credential stuffing from other breaches

2. LinkedIn (2012)
   - SHA1 without salt
   - 117 million passwords leaked
   - No rate limiting on brute force
   - Passwords cracked within days

3. Yahoo (2013-2014)
   - 3 billion accounts compromised
   - Weak security questions
   - No MFA option
   - MD5 hashing

4. GitHub (2020)
   - No rate limiting on password reset tokens
   - $10,000 bug bounty
   - Could brute force 6-digit tokens
   - Fixed: cryptographically secure tokens

5. Equifax (2017)
   - Admin portal: admin/admin
   - No MFA on sensitive systems
   - Led to 147M records exposed
   - $700M settlement

6. Twitter Bitcoin Hack (2020)
   - No MFA for admin tools
   - Social engineering attack
   - Compromised high-profile accounts
   - $121,000 stolen in Bitcoin

KEY LESSONS:
- Always use bcrypt for passwords
- Implement rate limiting
- Require MFA for admin accounts
- Use cryptographically secure tokens
- Generic error messages
- Session regeneration on login
"""

if __name__ == '__main__':
    print("OWASP A07:2021 - Authentication Failures Examples")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- Weak password policies")
    print("- Brute force vulnerabilities")
    print("- Username enumeration")
    print("- Session management flaws")
    print("- Insecure password reset")
    print("- Missing MFA")
    print("\nSecure implementations include:")
    print("✅ Strong password validation")
    print("✅ Rate limiting with exponential backoff")
    print("✅ Secure session management")
    print("✅ Cryptographically secure tokens")
    print("✅ Multi-factor authentication")


