"""
Vulnerable Code Examples for Security Interview Practice

WARNING: This code contains intentional security vulnerabilities for educational purposes.
DO NOT use any of these patterns in production code!

Practice Objective: 
- Identify ALL security vulnerabilities in each function
- Explain the risk and potential impact
- Provide secure alternatives

Each function has comments indicating how many vulnerabilities to find.
Solutions are provided at the bottom of the file.
"""

import hashlib
import jwt
import sqlite3
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
import pickle
import subprocess
import os

app = Flask(__name__)

# Global "database" (in-memory for examples)
users_db = {}
sessions = {}
SECRET_KEY = "super_secret_key_123"  # Vulnerability already!

# ==============================================================================
# EXAMPLE 1: User Authentication System
# Find: 8 vulnerabilities
# ==============================================================================

@app.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    
    # Hash password
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Store user
    users_db[username] = {
        'password': password_hash,
        'email': email,
        'role': 'user'
    }
    
    return jsonify({"message": "User registered successfully"})


@app.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Hash provided password
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Check credentials
    if username in users_db:
        if users_db[username]['password'] == password_hash:
            # Create session token
            token = jwt.encode({
                'username': username,
                'role': users_db[username]['role'],
                'exp': datetime.utcnow() + timedelta(days=30)
            }, SECRET_KEY, algorithm='HS256')
            
            return jsonify({
                "token": token,
                "message": "Login successful"
            })
        else:
            return jsonify({"error": "Invalid password"}), 401
    else:
        return jsonify({"error": "Username not found"}), 404


# ==============================================================================
# EXAMPLE 2: Payment Processing API
# Find: 7 vulnerabilities
# ==============================================================================

@app.route('/api/payment', methods=['POST'])
def process_payment():
    """Process payment transaction"""
    user_id = request.form.get('user_id')
    amount = request.form.get('amount')
    card_number = request.form.get('card_number')
    recipient = request.form.get('recipient')
    
    # Connect to database
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    
    # Check user balance
    query = f"SELECT balance FROM accounts WHERE user_id = '{user_id}'"
    cursor.execute(query)
    result = cursor.fetchone()
    balance = result[0]
    
    # Process payment
    if float(balance) >= float(amount):
        # Deduct from sender
        query = f"UPDATE accounts SET balance = balance - {amount} WHERE user_id = '{user_id}'"
        cursor.execute(query)
        
        # Add to recipient
        query = f"UPDATE accounts SET balance = balance + {amount} WHERE user_id = '{recipient}'"
        cursor.execute(query)
        
        # Log transaction
        print(f"Payment processed: {user_id} -> {recipient}, Amount: {amount}, Card: {card_number}")
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"Transferred ${amount} to {recipient}",
            "remaining_balance": float(balance) - float(amount)
        })
    else:
        return jsonify({"success": False, "message": "Insufficient funds"}), 400


# ==============================================================================
# EXAMPLE 3: User Profile Management
# Find: 6 vulnerabilities
# ==============================================================================

@app.route('/profile/<user_id>')
def get_profile(user_id):
    """Get user profile"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Get user data
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "ssn": user[3],
            "credit_card": user[4],
            "password_hash": user[5]
        })
    else:
        return jsonify({"error": "User not found"}), 404


@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Update user profile"""
    user_id = request.form.get('user_id')
    new_email = request.form.get('email')
    new_role = request.form.get('role')  # Users can set their own role!
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    query = f"UPDATE users SET email = '{new_email}', role = '{new_role}' WHERE id = {user_id}"
    cursor.execute(query)
    conn.commit()
    
    return jsonify({"message": "Profile updated successfully"})


# ==============================================================================
# EXAMPLE 4: File Upload and Processing
# Find: 5 vulnerabilities
# ==============================================================================

@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload file"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    filename = file.filename
    
    # Save file
    filepath = f"/uploads/{filename}"
    file.save(filepath)
    
    return jsonify({
        "message": "File uploaded successfully",
        "filename": filename,
        "path": filepath
    })


@app.route('/process_file', methods=['POST'])
def process_file():
    """Process uploaded file"""
    filename = request.form.get('filename')
    action = request.form.get('action')  # compress, extract, convert, etc.
    
    # Build command
    command = f"{action} /uploads/{filename}"
    
    # Execute command
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return jsonify({
        "output": result.stdout,
        "error": result.stderr
    })


# ==============================================================================
# EXAMPLE 5: API Key Management
# Find: 6 vulnerabilities
# ==============================================================================

API_KEYS = {
    "sk_live_123456789": {"user": "admin", "permissions": ["read", "write", "delete"]},
    "sk_test_987654321": {"user": "test_user", "permissions": ["read"]}
}


@app.route('/api/data')
def get_data():
    """Get sensitive data with API key authentication"""
    api_key = request.args.get('api_key')
    
    if api_key in API_KEYS:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM sensitive_data")
        data = cursor.fetchall()
        
        return jsonify({"data": data})
    else:
        return jsonify({"error": "Invalid API key"}), 401


@app.route('/api/create_key', methods=['POST'])
def create_api_key():
    """Create new API key"""
    username = request.form.get('username')
    permissions = request.form.get('permissions').split(',')
    
    # Generate API key
    key = "sk_live_" + hashlib.md5(username.encode()).hexdigest()[:16]
    
    API_KEYS[key] = {
        "user": username,
        "permissions": permissions
    }
    
    return jsonify({
        "api_key": key,
        "message": "API key created"
    })


# ==============================================================================
# EXAMPLE 6: Search and Filtering
# Find: 4 vulnerabilities
# ==============================================================================

@app.route('/search')
def search():
    """Search users"""
    query_param = request.args.get('q')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Search query
    sql = f"SELECT username, email FROM users WHERE username LIKE '%{query_param}%'"
    cursor.execute(sql)
    results = cursor.fetchall()
    
    # Return results in HTML
    html = f"<h1>Search Results for: {query_param}</h1>"
    html += "<ul>"
    for user in results:
        html += f"<li>{user[0]} - {user[1]}</li>"
    html += "</ul>"
    
    return render_template_string(html)


# ==============================================================================
# EXAMPLE 7: Session Management
# Find: 5 vulnerabilities
# ==============================================================================

@app.route('/create_session', methods=['POST'])
def create_session():
    """Create user session"""
    user_id = request.form.get('user_id')
    
    # Generate session ID
    session_id = hashlib.md5(user_id.encode()).hexdigest()
    
    # Store session (no expiration!)
    sessions[session_id] = {
        "user_id": user_id,
        "created_at": datetime.now().isoformat()
    }
    
    return jsonify({"session_id": session_id})


@app.route('/admin/users')
def admin_users():
    """Admin endpoint to list all users"""
    session_id = request.args.get('session_id')
    
    if session_id in sessions:
        # No role check - anyone with valid session can access!
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        return jsonify({"users": users})
    else:
        return jsonify({"error": "Invalid session"}), 401


# ==============================================================================
# EXAMPLE 8: Data Export
# Find: 4 vulnerabilities
# ==============================================================================

@app.route('/export/user_data')
def export_user_data():
    """Export user data"""
    user_id = request.args.get('user_id')
    export_format = request.args.get('format', 'json')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user_data = cursor.fetchone()
    
    if export_format == 'pickle':
        # Serialize with pickle
        serialized = pickle.dumps(user_data)
        return serialized
    else:
        return jsonify(user_data)


@app.route('/import/user_data', methods=['POST'])
def import_user_data():
    """Import user data"""
    data = request.data
    
    # Deserialize
    user_data = pickle.loads(data)
    
    # Insert into database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)", user_data)
    conn.commit()
    
    return jsonify({"message": "Data imported successfully"})


# ==============================================================================
# EXAMPLE 9: OAuth-like Implementation
# Find: 7 vulnerabilities
# ==============================================================================

AUTH_CODES = {}
ACCESS_TOKENS = {}


@app.route('/oauth/authorize')
def oauth_authorize():
    """OAuth authorization endpoint"""
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    
    # Generate authorization code
    auth_code = hashlib.md5(client_id.encode()).hexdigest()[:16]
    
    AUTH_CODES[auth_code] = {
        'client_id': client_id,
        'scope': scope,
        'redirect_uri': redirect_uri
    }
    
    # Redirect back to client
    return f"<script>window.location.href='{redirect_uri}?code={auth_code}'</script>"


@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    """OAuth token endpoint"""
    code = request.form.get('code')
    client_id = request.form.get('client_id')
    
    if code in AUTH_CODES:
        auth_data = AUTH_CODES[code]
        
        # Generate access token (never expires!)
        access_token = jwt.encode({
            'client_id': client_id,
            'scope': auth_data['scope']
        }, SECRET_KEY, algorithm='HS256')
        
        ACCESS_TOKENS[access_token] = auth_data
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer'
        })
    else:
        return jsonify({"error": "Invalid code"}), 400


# ==============================================================================
# EXAMPLE 10: AI/LLM Integration
# Find: 5 vulnerabilities
# ==============================================================================

def call_llm(prompt):
    """Simulate LLM API call"""
    # In real code, this would call OpenAI, etc.
    return f"AI Response to: {prompt}"


@app.route('/ai/chat', methods=['POST'])
def ai_chat():
    """AI chatbot endpoint"""
    user_message = request.form.get('message')
    user_id = request.form.get('user_id')
    
    # Get user data for context
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user_data = cursor.fetchone()
    
    # Build prompt with user data
    system_prompt = f"""
    You are a helpful assistant for user {user_data[1]}.
    User email: {user_data[2]}
    User account balance: ${user_data[3]}
    
    User question: {user_message}
    
    Provide a helpful response.
    """
    
    # Call LLM
    response = call_llm(system_prompt)
    
    # Log conversation (including sensitive data!)
    print(f"[AI CHAT LOG] User: {user_data[1]}, Message: {user_message}, Response: {response}")
    
    return jsonify({"response": response})


# ==============================================================================
# SOLUTIONS SECTION
# ==============================================================================

"""
SOLUTIONS - Try to find all vulnerabilities before looking here!

EXAMPLE 1: User Authentication System (8 vulnerabilities)
1. Weak hashing algorithm (MD5) - use bcrypt
2. Hardcoded secret key - use environment variable
3. No rate limiting - add rate limiter
4. No input validation - validate username/password format
5. Timing attack on username check - use constant-time comparison
6. Long token expiration (30 days) - use shorter expiration + refresh token
7. No password strength requirements - enforce strong passwords
8. Token not bound to client - add client identifier

EXAMPLE 2: Payment Processing API (7 vulnerabilities)
1. SQL injection in all queries - use parameterized queries
2. No authentication - require authentication
3. No authorization - verify user owns source account
4. Race condition in balance check/update - use transaction
5. No input validation - validate amount, user_id
6. Logging sensitive data (card number) - redact PII
7. Information disclosure - don't return exact balance to unauthorized users

EXAMPLE 3: User Profile Management (6 vulnerabilities)
1. SQL injection - use parameterized queries
2. No authentication - require authentication
3. IDOR - verify user can only access own profile
4. Information disclosure - don't return SSN, credit card, password hash
5. Privilege escalation - users shouldn't set their own role
6. No input validation - validate all inputs

EXAMPLE 4: File Upload and Processing (5 vulnerabilities)
1. Path traversal - validate filename, use secure path joining
2. No file type validation - check file extension/MIME type
3. Command injection - never use shell=True, validate inputs
4. Arbitrary command execution - whitelist allowed actions
5. No authentication/authorization - require auth

EXAMPLE 5: API Key Management (6 vulnerabilities)
1. Hardcoded API keys - store securely
2. API key in URL parameter - use Authorization header
3. Predictable key generation - use cryptographically secure random
4. No rate limiting - add rate limiting
5. Keys returned in response - only show once on creation
6. No key expiration - implement key rotation

EXAMPLE 6: Search and Filtering (4 vulnerabilities)
1. SQL injection - use parameterized queries
2. XSS (Cross-Site Scripting) - escape output in HTML
3. No authentication - require authentication
4. Information disclosure - limit search results

EXAMPLE 7: Session Management (5 vulnerabilities)
1. Predictable session ID - use cryptographically secure random
2. No session expiration - implement timeout
3. No session invalidation on logout - implement logout
4. Missing authorization check - verify user role for admin endpoints
5. Session fixation possible - regenerate session ID after login

EXAMPLE 8: Data Export (4 vulnerabilities)
1. SQL injection - use parameterized queries
2. Insecure deserialization (pickle) - use JSON instead
3. No authentication - require authentication
4. IDOR - verify user can only export own data

EXAMPLE 9: OAuth Implementation (7 vulnerabilities)
1. No redirect URI validation - whitelist redirect URIs
2. No state parameter - implement CSRF protection
3. No PKCE - implement PKCE for public clients
4. Authorization code not single-use - delete after use
5. No token expiration - implement short-lived tokens
6. Auth code not bound to client - verify client_id
7. No client authentication - verify client secret

EXAMPLE 10: AI/LLM Integration (5 vulnerabilities)
1. SQL injection - use parameterized queries
2. Prompt injection - user message directly in prompt
3. PII leakage to LLM - don't send sensitive data to LLM
4. Logging sensitive data - redact PII from logs
5. No input validation - validate and sanitize user input

==============================================================================
SECURE ALTERNATIVES
==============================================================================

Here's how to fix EXAMPLE 1 (Authentication):

from flask_limiter import Limiter
import bcrypt
import secrets
import os

# Load secret from environment
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

# Add rate limiting
limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/register_secure', methods=['POST'])
@limiter.limit("5 per hour")
def register_secure():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    email = request.form.get('email', '').strip()
    
    # Input validation
    if not username or not password or not email:
        return jsonify({"error": "All fields required"}), 400
    
    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400
    
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email"}), 400
    
    # Check if user exists
    if username in users_db:
        return jsonify({"error": "Username already exists"}), 409
    
    # Hash password with bcrypt
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    # Store user
    users_db[username] = {
        'password_hash': password_hash,
        'email': email,
        'role': 'user'
    }
    
    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login_secure', methods=['POST'])
@limiter.limit("10 per minute")
def login_secure():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Input validation
    if not username or not password:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Constant-time lookup and comparison
    user = users_db.get(username)
    
    if user and bcrypt.checkpw(password.encode(), user['password_hash']):
        # Create short-lived access token
        access_token = jwt.encode({
            'username': username,
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(minutes=15),
            'jti': secrets.token_urlsafe(16)  # Unique token ID
        }, SECRET_KEY, algorithm='HS256')
        
        # Create refresh token (stored in database, revocable)
        refresh_token = secrets.token_urlsafe(32)
        # Store refresh token in database with expiration
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": 900  # 15 minutes
        }), 200
    else:
        # Generic error message (don't reveal if username exists)
        return jsonify({"error": "Invalid credentials"}), 401


def is_valid_email(email):
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

==============================================================================

Practice Exercise:
1. Review each example above
2. Identify ALL vulnerabilities (don't look at solutions first!)
3. Write secure versions of the vulnerable functions
4. Explain WHY each vulnerability is dangerous
5. Explain HOW your fix prevents the vulnerability

This is exactly the type of code review you might encounter in a PayPal interview!
"""

if __name__ == '__main__':
    print("WARNING: This code contains intentional vulnerabilities!")
    print("Use for educational purposes only.")
    print("DO NOT run this server in production!")
    print("\nReview the code and try to find all vulnerabilities.")

