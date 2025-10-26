"""
OWASP A08:2021 - Software and Data Integrity Failures
=======================================================

Software and data integrity failures relate to code and infrastructure that does
not protect against integrity violations. An example is where objects or data are
encoded or serialized into a structure that an attacker can see and modify.

Common vulnerabilities:
- Insecure deserialization
- Missing digital signatures
- Unsigned software updates
- Insecure CI/CD pipeline
- No integrity verification
- Tampering with serialized objects
"""

from flask import Flask, request, jsonify
import pickle
import json
import base64
import hashlib
import hmac
import jwt

app = Flask(__name__)
app.secret_key = 'change-me-in-production'

# ============================================================================
# VULNERABLE CODE EXAMPLES
# ============================================================================

# Example 1: Insecure Deserialization with Pickle
@app.route('/api/save_session', methods=['POST'])
def save_session_vulnerable():
    """
    VULNERABILITY: Insecure pickle deserialization
    
    Attack: Craft malicious pickle payload for RCE
    Impact: Remote Code Execution
    """
    data = request.get_json()
    user_data = data.get('user_data')
    
    # Serialize user data with pickle (DANGEROUS!)
    serialized = pickle.dumps(user_data)
    encoded = base64.b64encode(serialized).decode()
    
    return jsonify({'session_token': encoded})


@app.route('/api/load_session', methods=['POST'])
def load_session_vulnerable():
    """
    VULNERABILITY: Unpickling untrusted data
    
    Attack: Send malicious pickle that executes arbitrary code
    Impact: Full server compromise
    """
    data = request.get_json()
    session_token = data.get('session_token')
    
    # Deserialize with pickle (DANGEROUS!)
    decoded = base64.b64decode(session_token)
    user_data = pickle.loads(decoded)  # RCE HERE!
    
    return jsonify({'user_data': user_data})


"""
ATTACK EXAMPLE: Malicious pickle payload

import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        # This will execute when unpickled!
        return (os.system, ('rm -rf /',))

malicious = pickle.dumps(RCE())
payload = base64.b64encode(malicious).decode()
# Send this payload to /api/load_session
"""


# Example 2: JWT Without Signature Verification
@app.route('/api/login_jwt_weak', methods=['POST'])
def login_jwt_weak():
    """
    VULNERABILITY: JWT created but not properly verified later
    
    Attack: Modify JWT payload (change user role)
    Impact: Privilege escalation
    """
    data = request.get_json()
    username = data.get('username')
    
    # Create JWT without strong secret
    token = jwt.encode(
        {'username': username, 'role': 'user'},
        'weak-secret',  # Weak secret!
        algorithm='HS256'
    )
    
    return jsonify({'token': token})


@app.route('/api/admin_jwt_weak')
def admin_jwt_weak():
    """
    VULNERABILITY: Doesn't verify JWT signature properly
    
    Attack: Set algorithm to 'none' or brute force weak secret
    Impact: Authentication bypass
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        # Doesn't verify signature!
        payload = jwt.decode(token, options={"verify_signature": False})
        
        if payload.get('role') == 'admin':
            return jsonify({'message': 'Admin access granted'})
        
    except:
        pass
    
    return jsonify({'error': 'Unauthorized'}), 401


# Example 3: No Integrity Check on File Upload
import os

UPLOAD_FOLDER = '/tmp/uploads'

@app.route('/api/upload_file', methods=['POST'])
def upload_file_vulnerable():
    """
    VULNERABILITY: No integrity verification
    
    Attack: Upload malicious file, MITM attack to replace file
    Impact: Malware distribution, code execution
    """
    file = request.files.get('file')
    filename = file.filename
    
    # No hash verification!
    # No signature check!
    # Trusts whatever is uploaded
    
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    
    return jsonify({'message': 'File uploaded'})


# Example 4: Insecure Software Update
@app.route('/api/check_update', methods=['GET'])
def check_update_vulnerable():
    """
    VULNERABILITY: No signature verification on updates
    
    Attack: MITM to serve malicious update
    Impact: Supply chain attack
    """
    # Returns update info without signature
    return jsonify({
        'version': '2.0.0',
        'download_url': 'http://updates.example.com/app-2.0.0.zip',
        # No signature or hash!
    })


# Example 5: Cookie Tampering
from flask import make_response

@app.route('/api/set_user_cookie')
def set_user_cookie_vulnerable():
    """
    VULNERABILITY: Cookie without integrity protection
    
    Attack: Modify cookie to change user ID or role
    Impact: Privilege escalation, impersonation
    """
    response = make_response(jsonify({'message': 'Cookie set'}))
    
    # No HMAC or signature!
    user_data = json.dumps({'user_id': 123, 'role': 'user'})
    response.set_cookie('user_data', user_data)
    
    return response


@app.route('/api/get_user_cookie')
def get_user_cookie_vulnerable():
    """
    VULNERABILITY: Trusts cookie without verification
    
    Attack: User modifies cookie to change role to 'admin'
    Impact: Authorization bypass
    """
    user_data_str = request.cookies.get('user_data', '{}')
    user_data = json.loads(user_data_str)  # Trusts cookie!
    
    if user_data.get('role') == 'admin':
        return jsonify({'message': 'Admin access', 'user_data': user_data})
    
    return jsonify({'message': 'User access', 'user_data': user_data})


# ============================================================================
# SECURE CODE EXAMPLES
# ============================================================================

# Example 1: SECURE - Use JSON instead of Pickle
@app.route('/api/save_session_secure', methods=['POST'])
def save_session_secure():
    """
    SECURE: Use JSON (safe serialization)
    
    Defense: JSON cannot execute code
    """
    data = request.get_json()
    user_data = data.get('user_data')
    
    # Only serialize safe data types
    allowed_types = (str, int, float, bool, list, dict, type(None))
    
    def is_safe(obj):
        """Recursively check if object is safe to serialize"""
        if isinstance(obj, allowed_types):
            if isinstance(obj, dict):
                return all(is_safe(k) and is_safe(v) for k, v in obj.items())
            elif isinstance(obj, list):
                return all(is_safe(item) for item in obj)
            return True
        return False
    
    if not is_safe(user_data):
        return jsonify({'error': 'Invalid data type'}), 400
    
    # Use JSON instead of pickle
    session_token = json.dumps(user_data)
    
    # Add HMAC for integrity
    signature = hmac.new(
        app.secret_key.encode(),
        session_token.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Combine data and signature
    signed_token = f"{session_token}.{signature}"
    encoded = base64.b64encode(signed_token.encode()).decode()
    
    return jsonify({'session_token': encoded})


@app.route('/api/load_session_secure', methods=['POST'])
def load_session_secure():
    """
    SECURE: Verify integrity before deserializing
    
    Defense: HMAC signature verification
    """
    data = request.get_json()
    session_token = data.get('session_token')
    
    try:
        # Decode
        decoded = base64.b64decode(session_token).decode()
        
        # Split data and signature
        if '.' not in decoded:
            return jsonify({'error': 'Invalid token'}), 401
        
        json_data, provided_signature = decoded.rsplit('.', 1)
        
        # Verify signature
        expected_signature = hmac.new(
            app.secret_key.encode(),
            json_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Constant-time comparison
        if not hmac.compare_digest(provided_signature, expected_signature):
            return jsonify({'error': 'Signature verification failed'}), 401
        
        # Safe to deserialize
        user_data = json.loads(json_data)
        
        return jsonify({'user_data': user_data})
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401


# Example 2: SECURE - JWT with Proper Verification
JWT_SECRET = 'use-strong-secret-from-env-32-chars-min'
JWT_ALGORITHM = 'HS256'

@app.route('/api/login_jwt_secure', methods=['POST'])
def login_jwt_secure():
    """
    SECURE: JWT with strong secret
    
    Defense: Strong secret, proper algorithm
    """
    data = request.get_json()
    username = data.get('username')
    
    # Create JWT with strong secret
    token = jwt.encode(
        {
            'username': username,
            'role': 'user',
            'exp': datetime.utcnow() + timedelta(hours=1)  # Expiration
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )
    
    return jsonify({'token': token})


@app.route('/api/admin_jwt_secure')
def admin_jwt_secure():
    """
    SECURE: Proper JWT verification
    
    Defense: Signature and expiration verification
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        # Verify signature AND expiration
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]  # Specific algorithm
        )
        
        # Check role
        if payload.get('role') != 'admin':
            return jsonify({'error': 'Insufficient privileges'}), 403
        
        return jsonify({'message': 'Admin access granted'})
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


# Example 3: SECURE - File Upload with Hash Verification
@app.route('/api/upload_file_secure', methods=['POST'])
def upload_file_secure():
    """
    SECURE: Verify file integrity with hash
    
    Defense: Client provides expected hash
    """
    file = request.files.get('file')
    expected_hash = request.form.get('file_hash')  # SHA256 hash
    filename = file.filename
    
    # Read file content
    content = file.read()
    
    # Calculate hash
    actual_hash = hashlib.sha256(content).hexdigest()
    
    # Verify integrity
    if actual_hash != expected_hash:
        return jsonify({'error': 'File integrity check failed'}), 400
    
    # Verify file type (additional check)
    import magic
    file_type = magic.from_buffer(content, mime=True)
    allowed_types = ['image/jpeg', 'image/png', 'application/pdf']
    
    if file_type not in allowed_types:
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Save file
    safe_path = os.path.join(UPLOAD_FOLDER, filename)
    with open(safe_path, 'wb') as f:
        f.write(content)
    
    return jsonify({
        'message': 'File uploaded',
        'hash': actual_hash
    })


# Example 4: SECURE - Software Update with Signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta

@app.route('/api/check_update_secure', methods=['GET'])
def check_update_secure():
    """
    SECURE: Update with digital signature
    
    Defense: RSA signature verification required
    """
    update_info = {
        'version': '2.0.0',
        'download_url': 'https://updates.example.com/app-2.0.0.zip',
        'sha256': 'abc123...',  # File hash
        'signature': 'def456...',  # RSA signature of hash
        'public_key': '-----BEGIN PUBLIC KEY-----\n...',
        'release_date': '2024-01-15',
        'min_version': '1.0.0'
    }
    
    return jsonify(update_info)


def verify_update_signature(file_hash, signature, public_key_pem):
    """
    SECURE: Verify update signature
    
    Defense: RSA signature verification
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    # Load public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    # Verify signature
    try:
        public_key.verify(
            base64.b64decode(signature),
            file_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# Example 5: SECURE - Signed Cookies
from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer(app.secret_key)

@app.route('/api/set_user_cookie_secure')
def set_user_cookie_secure():
    """
    SECURE: Cryptographically signed cookie
    
    Defense: Tamper-proof cookies with itsdangerous
    """
    response = make_response(jsonify({'message': 'Cookie set'}))
    
    user_data = {'user_id': 123, 'role': 'user'}
    
    # Sign the cookie
    signed_data = serializer.dumps(user_data)
    
    response.set_cookie(
        'user_data',
        signed_data,
        httponly=True,  # Prevent JavaScript access
        secure=True,    # HTTPS only
        samesite='Lax'  # CSRF protection
    )
    
    return response


@app.route('/api/get_user_cookie_secure')
def get_user_cookie_secure():
    """
    SECURE: Verify cookie signature
    
    Defense: Reject tampered cookies
    """
    signed_data = request.cookies.get('user_data')
    
    if not signed_data:
        return jsonify({'error': 'No cookie found'}), 401
    
    try:
        # Verify signature and expiration (max_age in seconds)
        user_data = serializer.loads(
            signed_data,
            max_age=3600  # 1 hour
        )
        
        if user_data.get('role') == 'admin':
            return jsonify({'message': 'Admin access', 'user_data': user_data})
        
        return jsonify({'message': 'User access', 'user_data': user_data})
        
    except Exception as e:
        return jsonify({'error': 'Invalid or expired cookie'}), 401


# ============================================================================
# CI/CD PIPELINE SECURITY
# ============================================================================

"""
SECURE CI/CD PIPELINE BEST PRACTICES:

Pipeline Integrity:
✅ Use signed commits (GPG)
✅ Require code review before merge
✅ Protected branches
✅ Signed container images
✅ Immutable build artifacts

Access Control:
✅ Least privilege for CI/CD
✅ Separate credentials per environment
✅ Rotate secrets regularly
✅ Use short-lived tokens
✅ Audit all pipeline changes

Artifact Security:
✅ Sign all artifacts
✅ Store in private registry
✅ Scan for vulnerabilities
✅ Version immutably (no overwrites)
✅ Maintain provenance

Dependencies:
✅ Pin dependency versions
✅ Use private mirror
✅ Verify checksums
✅ Scan for vulnerabilities
✅ SBOM generation

GITHUB ACTIONS SECURE EXAMPLE:

name: Secure Build

on:
  push:
    branches: [ main ]

permissions:
  contents: read
  packages: write

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
      with:
        token: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Verify commit signature
      run: |
        git verify-commit HEAD || exit 1
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install safety
    
    - name: Security scan
      run: |
        safety check
        bandit -r .
    
    - name: Build artifact
      run: |
        python setup.py sdist bdist_wheel
    
    - name: Generate checksum
      run: |
        sha256sum dist/* > checksums.txt
    
    - name: Sign artifact
      run: |
        gpg --armor --detach-sign checksums.txt
    
    - name: Upload artifact
      uses: actions/upload-artifact@v3
      with:
        name: package
        path: |
          dist/*
          checksums.txt
          checksums.txt.asc
"""

# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
INTEGRITY FAILURE PREVENTION:

Serialization:
✅ Never use pickle/marshal with untrusted data
✅ Use JSON for data serialization
✅ Validate data types before serialization
✅ Use schema validation (JSON Schema)

Signing:
✅ Use HMAC for data integrity
✅ Use digital signatures for critical operations
✅ Verify signatures before processing
✅ Use constant-time comparison

JWT:
✅ Use strong secrets (32+ bytes, random)
✅ Specify algorithm explicitly
✅ Verify signature AND expiration
✅ Never use 'none' algorithm
✅ Rotate secrets periodically

File Integrity:
✅ Verify file hashes
✅ Check digital signatures
✅ Validate file types
✅ Scan for malware
✅ Use checksums for downloads

Software Updates:
✅ Sign all updates
✅ Verify signatures before installation
✅ Use HTTPS for downloads
✅ Check version authenticity
✅ Maintain update changelog

CI/CD:
✅ Sign commits (GPG)
✅ Protected branches
✅ Code review required
✅ Scan dependencies
✅ Sign artifacts
✅ Immutable builds

CODE CHECKLIST:

✅ No pickle/marshal for untrusted data
✅ JSON with schema validation
✅ HMAC for data integrity
✅ JWT properly verified
✅ Strong secrets (>32 bytes)
✅ File hash verification
✅ Digital signatures for critical ops
✅ Signed software updates
✅ Secure CI/CD pipeline
✅ Audit logging enabled
"""

# ============================================================================
# REAL-WORLD EXAMPLES
# ============================================================================

"""
REAL-WORLD INTEGRITY FAILURES:

1. SOLARWINDS (2020)
   - Compromised build system
   - Malicious code in updates
   - 18,000+ customers affected
   - $100M+ in damages
   - Issue: No signature verification on build

2. CODECOV (2021)
   - Compromised Bash Uploader script
   - Credential theft from CI/CD
   - Hundreds of customers affected
   - Issue: No integrity check on script

3. EVENT-STREAM NPM (2018)
   - Malicious code in popular package
   - Cryptocurrency wallet theft
   - 8 million downloads
   - Issue: No package signing

4. UA-PARSER-JS (2021)
   - NPM package hijacked
   - Cryptocurrency miners injected
   - 6-7 million weekly downloads
   - Issue: Compromised maintainer account

5. NOTPETYA (2017)
   - Ukrainian accounting software update
   - Ransomware disguised as update
   - $10 billion in damages
   - Issue: Update not properly signed

KEY LESSONS:
- Always verify signatures
- Sign all software updates
- Secure CI/CD pipelines
- Never deserialize untrusted data
- Use integrity checks (HMAC, signatures)
- Monitor for tampering
"""

if __name__ == '__main__':
    print("OWASP A08:2021 - Software and Data Integrity Failures")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- Insecure deserialization (pickle)")
    print("- JWT without proper verification")
    print("- Missing integrity checks")
    print("- Cookie tampering")
    print("- Unsigned software updates")
    print("\nSecure implementations include:")
    print("✅ JSON serialization with HMAC")
    print("✅ Proper JWT verification")
    print("✅ File hash verification")
    print("✅ Digital signatures")
    print("✅ Signed cookies (itsdangerous)")


