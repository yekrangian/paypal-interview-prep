"""
OWASP A01:2021 - Broken Access Control
==========================================

Access control enforces policy such that users cannot act outside of their intended 
permissions. Failures typically lead to unauthorized information disclosure, 
modification, or destruction of data.

Common vulnerabilities:
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Privilege escalation (vertical and horizontal)
- Forced browsing to authenticated pages
- Metadata manipulation (JWT, cookies)
"""

from flask import Flask, request, jsonify, session
from functools import wraps
import sqlite3

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# ============================================================================
# VULNERABLE CODE EXAMPLES
# ============================================================================

# Example 1: Insecure Direct Object Reference (IDOR)
@app.route('/api/user/<int:user_id>/profile', methods=['GET'])
def get_user_profile_vulnerable(user_id):
    """
    VULNERABILITY: No authorization check - any user can view any profile
    
    Attack: User with ID 5 can access /api/user/10/profile
    Impact: Unauthorized access to other users' data
    """
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # No check if current user has permission to view this profile
    cursor.execute("SELECT id, username, email, ssn, salary FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    
    if user_data:
        return jsonify({
            'id': user_data[0],
            'username': user_data[1],
            'email': user_data[2],
            'ssn': user_data[3],  # Sensitive data exposed!
            'salary': user_data[4]  # Sensitive data exposed!
        })
    return jsonify({'error': 'User not found'}), 404


# Example 2: Missing Function-Level Access Control
@app.route('/api/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user_vulnerable(user_id):
    """
    VULNERABILITY: No admin check - any authenticated user can delete users
    
    Attack: Regular user calls this endpoint to delete other users
    Impact: Unauthorized data deletion
    """
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    
    return jsonify({'message': 'User deleted successfully'})


# Example 3: Privilege Escalation via Parameter Manipulation
@app.route('/api/user/update_profile', methods=['POST'])
def update_profile_vulnerable():
    """
    VULNERABILITY: User can modify their role via request parameter
    
    Attack: User sends {"role": "admin"} to escalate privileges
    Impact: Privilege escalation to admin
    """
    user_id = session.get('user_id')
    data = request.get_json()
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Directly uses all fields from request - including role!
    cursor.execute("""
        UPDATE users 
        SET username = ?, email = ?, role = ? 
        WHERE id = ?
    """, (data.get('username'), data.get('email'), data.get('role'), user_id))
    conn.commit()
    
    return jsonify({'message': 'Profile updated'})


# Example 4: Broken Access Control in File Downloads
@app.route('/api/download', methods=['GET'])
def download_file_vulnerable():
    """
    VULNERABILITY: Path traversal + no ownership check
    
    Attack: /api/download?file=../../../etc/passwd
    Impact: Arbitrary file access on server
    """
    filename = request.args.get('file')
    
    # No validation or authorization
    filepath = f"/uploads/{filename}"
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        return content
    except:
        return jsonify({'error': 'File not found'}), 404


# ============================================================================
# SECURE CODE EXAMPLES
# ============================================================================

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check if user is admin
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or user[0] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


# Example 1: SECURE - IDOR Prevention with Authorization Check
@app.route('/api/user/<int:user_id>/profile/secure', methods=['GET'])
@require_auth
def get_user_profile_secure(user_id):
    """
    SECURE: Proper authorization check before data access
    
    Defense: Verify current user has permission to view this profile
    """
    current_user_id = session.get('user_id')
    
    # Authorization check: User can only view their own profile
    if current_user_id != user_id:
        return jsonify({'error': 'Forbidden - can only view own profile'}), 403
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, email 
        FROM users 
        WHERE id = ?
    """, (user_id,))
    user_data = cursor.fetchone()
    
    if user_data:
        return jsonify({
            'id': user_data[0],
            'username': user_data[1],
            'email': user_data[2]
            # Sensitive fields (SSN, salary) not included
        })
    return jsonify({'error': 'User not found'}), 404


# Example 2: SECURE - Function-Level Access Control
@app.route('/api/admin/delete_user/<int:user_id>/secure', methods=['DELETE'])
@require_admin  # Admin check enforced
def delete_user_secure(user_id):
    """
    SECURE: Admin role required to delete users
    
    Defense: @require_admin decorator enforces admin access
    """
    # Additional check: Can't delete yourself
    if session.get('user_id') == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    
    return jsonify({'message': 'User deleted successfully'})


# Example 3: SECURE - Prevent Privilege Escalation
@app.route('/api/user/update_profile/secure', methods=['POST'])
@require_auth
def update_profile_secure():
    """
    SECURE: Whitelist allowed fields, prevent role modification
    
    Defense: Only allow specific fields to be updated
    """
    user_id = session.get('user_id')
    data = request.get_json()
    
    # Whitelist of allowed fields
    ALLOWED_FIELDS = ['username', 'email', 'bio']
    
    # Extract only allowed fields
    update_data = {k: v for k, v in data.items() if k in ALLOWED_FIELDS}
    
    if not update_data:
        return jsonify({'error': 'No valid fields to update'}), 400
    
    # Build dynamic query with only allowed fields
    fields = ', '.join([f"{k} = ?" for k in update_data.keys()])
    values = list(update_data.values()) + [user_id]
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"UPDATE users SET {fields} WHERE id = ?", values)
    conn.commit()
    
    return jsonify({'message': 'Profile updated'})


# Example 4: SECURE - File Download with Authorization
@app.route('/api/download/secure', methods=['GET'])
@require_auth
def download_file_secure():
    """
    SECURE: Path validation + ownership verification
    
    Defense: 
    1. Validate filename (no path traversal)
    2. Verify user owns the file
    3. Use whitelist of allowed directories
    """
    import os
    from werkzeug.utils import secure_filename
    
    filename = request.args.get('file')
    user_id = session.get('user_id')
    
    # Validate filename (prevent path traversal)
    safe_filename = secure_filename(filename)
    if safe_filename != filename:
        return jsonify({'error': 'Invalid filename'}), 400
    
    # Check file ownership in database
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT filepath 
        FROM user_files 
        WHERE user_id = ? AND filename = ?
    """, (user_id, safe_filename))
    file_record = cursor.fetchone()
    
    if not file_record:
        return jsonify({'error': 'File not found or access denied'}), 403
    
    # Construct safe path (within allowed directory)
    UPLOAD_DIR = '/uploads'
    filepath = os.path.join(UPLOAD_DIR, str(user_id), safe_filename)
    
    # Verify path is within allowed directory (prevent symlink attacks)
    if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_DIR)):
        return jsonify({'error': 'Invalid file path'}), 400
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404


# ============================================================================
# TESTING ATTACK SCENARIOS
# ============================================================================

def test_idor_attack():
    """
    Test: IDOR vulnerability
    
    Scenario: User 5 tries to access User 10's profile
    """
    print("\n=== Testing IDOR Attack ===")
    
    # Attacker (user_id=5) tries to access victim's profile (user_id=10)
    print("Vulnerable endpoint: /api/user/10/profile")
    print("❌ Attack succeeds - returns sensitive data (SSN, salary)")
    
    print("\nSecure endpoint: /api/user/10/profile/secure")
    print("✅ Attack blocked - 403 Forbidden (can only view own profile)")


def test_privilege_escalation():
    """
    Test: Privilege escalation via parameter manipulation
    
    Scenario: Regular user tries to make themselves admin
    """
    print("\n=== Testing Privilege Escalation ===")
    
    payload = {
        "username": "hacker",
        "email": "hacker@evil.com",
        "role": "admin"  # Attempting to escalate privileges
    }
    
    print("Vulnerable endpoint: POST /api/user/update_profile")
    print(f"Payload: {payload}")
    print("❌ Attack succeeds - user becomes admin")
    
    print("\nSecure endpoint: POST /api/user/update_profile/secure")
    print("✅ Attack blocked - 'role' field ignored (not in whitelist)")


# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
ACCESS CONTROL BEST PRACTICES:

1. Deny by Default
   - Deny access unless explicitly granted
   - Implement access control at trusted service layer

2. Enforce Access Control Server-Side
   - Never rely on client-side checks
   - Validate on every request

3. Use Indirect Object References
   - Don't expose internal IDs
   - Use UUIDs or session-based references

4. Implement Proper Authorization
   - Check user permissions on every data access
   - Verify both authentication and authorization

5. Log Access Control Failures
   - Monitor for suspicious patterns
   - Alert on repeated access violations

6. Rate Limit Sensitive Operations
   - Prevent enumeration attacks
   - Slow down attackers

7. Use Attribute or Feature-Based Access Control
   - Define permissions based on attributes
   - Centralize access control logic

8. Test Access Controls
   - Unit test authorization logic
   - Penetration test for IDOR vulnerabilities
   - Test with different user roles

CODE CHECKLIST:

✅ Authentication check on every protected endpoint
✅ Authorization check before data access
✅ Validate user owns the resource
✅ Whitelist allowed fields for updates
✅ Use role-based or attribute-based access control
✅ Sanitize and validate all inputs
✅ Log access control failures
✅ Use secure defaults (deny by default)
✅ Implement proper session management
✅ Test with different user roles and edge cases
"""

# ============================================================================
# REAL-WORLD EXAMPLES
# ============================================================================

"""
REAL-WORLD BROKEN ACCESS CONTROL BREACHES:

1. Facebook (2018)
   - IDOR vulnerability in photo API
   - Exposed 6.8 million users' private photos
   - Attackers could access photos not shared publicly

2. T-Mobile (2021)
   - Weak API authentication
   - 40 million customers' data exposed
   - Attacker gained admin access

3. Parler (2021)
   - Sequential IDs with no authorization checks
   - All posts, videos, user data scraped
   - 70TB of data downloaded

4. Venmo (2019)
   - Default public transaction history
   - Users' financial transactions exposed
   - Privacy violation at scale

5. Uber (2016)
   - Admin panel accessible without proper authentication
   - 57 million users' data compromised
   - Driver's license numbers exposed

KEY LESSON: Always verify authorization before accessing data!
"""

if __name__ == '__main__':
    print("OWASP A01:2021 - Broken Access Control Examples")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- IDOR vulnerabilities")
    print("- Missing function-level access control")
    print("- Privilege escalation")
    print("- Secure implementations with proper authorization")
    
    # Run test scenarios
    test_idor_attack()
    test_privilege_escalation()
    
    print("\n" + "=" * 60)
    print("Study both vulnerable and secure examples!")
    print("Practice identifying authorization flaws in code reviews.")

