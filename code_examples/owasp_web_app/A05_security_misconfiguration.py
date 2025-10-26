"""
OWASP A05:2021 - Security Misconfiguration
============================================

Security misconfiguration is the most commonly seen issue. This is commonly a
result of insecure default configurations, incomplete configurations, open cloud
storage, misconfigured HTTP headers, and verbose error messages containing
sensitive information.

Common vulnerabilities:
- Missing security headers
- Default credentials
- Unnecessary features enabled
- Verbose error messages
- Unpatched systems
- Directory listing enabled
- Insecure default configurations
"""

from flask import Flask, request, jsonify
import os
import traceback

app = Flask(__name__)

# ============================================================================
# VULNERABLE CODE EXAMPLES
# ============================================================================

# Example 1: Debug Mode in Production
# VULNERABILITY: Debug mode exposes sensitive information
app.config['DEBUG'] = True  # NEVER in production!
app.config['TESTING'] = True


@app.route('/api/user/<int:user_id>')
def get_user_debug(user_id):
    """
    VULNERABILITY: Debug mode enabled in production
    
    Attack: Errors expose stack traces, source code, environment variables
    Impact: Information disclosure, potential RCE via debug console
    """
    # Intentional error to show debug page
    result = 1 / 0  # Division by zero
    return jsonify({'user': result})


# Example 2: Verbose Error Messages
@app.route('/api/login_verbose', methods=['POST'])
def login_verbose_errors():
    """
    VULNERABILITY: Detailed error messages expose system information
    
    Attack: Error messages reveal database structure, file paths
    Impact: Information disclosure aids further attacks
    """
    try:
        data = request.get_json()
        username = data.get('username')
        
        import sqlite3
        conn = sqlite3.connect('/var/www/app/database/users.db')
        cursor = conn.cursor()
        
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        
    except Exception as e:
        # Exposing full error details!
        return jsonify({
            'error': str(e),
            'type': type(e).__name__,
            'traceback': traceback.format_exc(),
            'file': __file__,
            'query': query  # Exposes SQL structure!
        }), 500


# Example 3: Missing Security Headers
@app.route('/api/data')
def missing_security_headers():
    """
    VULNERABILITY: Missing security headers
    
    Attack: XSS, clickjacking, MIME sniffing attacks
    Impact: Browser doesn't apply security protections
    """
    # No security headers set!
    # Missing:
    # - X-Content-Type-Options
    # - X-Frame-Options
    # - Content-Security-Policy
    # - Strict-Transport-Security
    
    return jsonify({'data': 'sensitive information'})


# Example 4: Default Credentials
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"  # Default password!

@app.route('/api/admin/login', methods=['POST'])
def admin_login_default():
    """
    VULNERABILITY: Default credentials not changed
    
    Attack: Attacker uses default admin/admin123
    Impact: Full admin access
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username == DEFAULT_ADMIN_USERNAME and password == DEFAULT_ADMIN_PASSWORD:
        return jsonify({'message': 'Admin access granted'})
    
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 5: Unnecessary Features Enabled
@app.route('/api/debug/env')
def expose_environment():
    """
    VULNERABILITY: Debug endpoints in production
    
    Attack: Access debug endpoints to view sensitive data
    Impact: Exposure of secrets, API keys, configuration
    """
    # Debug endpoint that shouldn't exist in production!
    return jsonify({
        'environment': dict(os.environ),
        'config': dict(app.config),
        'python_path': os.sys.path
    })


@app.route('/api/debug/routes')
def expose_routes():
    """
    VULNERABILITY: Exposing application structure
    
    Attack: Map all endpoints and find attack surface
    Impact: Information disclosure
    """
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'path': str(rule)
        })
    return jsonify({'routes': routes})


# Example 6: Directory Listing Enabled
@app.route('/files/<path:filename>')
def serve_file_vulnerable(filename):
    """
    VULNERABILITY: Directory traversal + listing
    
    Attack: Browse server directory structure
    Impact: Access to sensitive files
    """
    import os
    from flask import send_file
    
    # No path validation!
    file_path = os.path.join('/var/www/uploads', filename)
    
    if os.path.isdir(file_path):
        # List directory contents - should be disabled!
        files = os.listdir(file_path)
        return jsonify({'files': files})
    
    return send_file(file_path)


# Example 7: Insecure CORS Configuration
@app.after_request
def insecure_cors(response):
    """
    VULNERABILITY: Overly permissive CORS
    
    Attack: Malicious site can access API
    Impact: CSRF, data theft
    """
    # Allows ALL origins!
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    
    return response


# Example 8: Exposed Sensitive Files
@app.route('/.env')
@app.route('/config.py')
@app.route('/.git/config')
def serve_config_files():
    """
    VULNERABILITY: Configuration files accessible via web
    
    Attack: Download .env, .git, config files
    Impact: Exposure of secrets, API keys, source code
    """
    # These files should NEVER be web-accessible!
    return "DATABASE_URL=postgresql://admin:password@localhost/db\nSECRET_KEY=super-secret-key"


# ============================================================================
# SECURE CODE EXAMPLES
# ============================================================================

# Example 1: SECURE - Proper Production Configuration
"""
SECURE Production Configuration:

# config.py
import os

class Config:
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Security headers
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Database
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '').split(',')

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

# Load based on environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}

app_config = config[os.environ.get('FLASK_ENV', 'production')]
"""


# Example 2: SECURE - Proper Error Handling
@app.errorhandler(Exception)
def handle_error_secure(error):
    """
    SECURE: Generic error messages to users
    
    Defense: Log details, show generic message
    """
    import logging
    
    # Log full error details for debugging
    logging.error(f"Error: {str(error)}", exc_info=True)
    logging.error(f"Request: {request.method} {request.url}")
    logging.error(f"User: {request.remote_addr}")
    
    # Return generic error to user
    return jsonify({
        'error': 'An error occurred',
        'request_id': 'abc123'  # For support reference
    }), 500


@app.route('/api/login_secure', methods=['POST'])
def login_secure_errors():
    """
    SECURE: Generic error messages
    
    Defense: No information disclosure
    """
    try:
        data = request.get_json()
        username = data.get('username')
        # Authentication logic here...
        
    except Exception as e:
        # Log internally
        import logging
        logging.error(f"Login error: {e}", exc_info=True)
        
        # Generic message to user
        return jsonify({
            'error': 'Login failed. Please try again.'
        }), 500


# Example 3: SECURE - Security Headers
@app.after_request
def add_security_headers(response):
    """
    SECURE: Comprehensive security headers
    
    Defense: Multiple browser security protections
    """
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    
    # HSTS - Force HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response


# Example 4: SECURE - CORS Configuration
from flask_cors import CORS

# Whitelist specific origins
ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://www.example.com'
]

CORS(app, 
     origins=ALLOWED_ORIGINS,
     methods=['GET', 'POST', 'PUT', 'DELETE'],
     allow_headers=['Content-Type', 'Authorization'],
     supports_credentials=True,
     max_age=3600)


# Example 5: SECURE - Disable Unnecessary Features
"""
SECURE: Remove debug endpoints in production

# middleware.py
def require_development_mode(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not app.config['DEBUG']:
            abort(404)  # Hide endpoint in production
        return f(*args, **kwargs)
    return decorated

@app.route('/api/debug/info')
@require_development_mode
def debug_info():
    return jsonify({'debug': 'info'})
"""


# Example 6: SECURE - File Serving
from werkzeug.utils import secure_filename
from flask import send_from_directory

UPLOAD_FOLDER = '/var/www/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/files/<path:filename>')
def serve_file_secure(filename):
    """
    SECURE: Safe file serving
    
    Defense: Validate filename, no directory listing
    """
    # Sanitize filename
    safe_filename = secure_filename(filename)
    
    if not safe_filename or not allowed_file(safe_filename):
        return jsonify({'error': 'Invalid file'}), 400
    
    # Verify file exists and is a file (not directory)
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    if not os.path.isfile(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    # Serve file from directory (prevents path traversal)
    return send_from_directory(UPLOAD_FOLDER, safe_filename)


# Example 7: SECURE - Protect Sensitive Files
"""
SECURE: Nginx configuration to block sensitive files

# /etc/nginx/sites-available/app

server {
    listen 80;
    server_name example.com;
    
    # Block access to sensitive files
    location ~ /\.(env|git|svn|htaccess) {
        deny all;
        return 404;
    }
    
    # Block access to config files
    location ~ \.(yml|yaml|conf|config|ini)$ {
        deny all;
        return 404;
    }
    
    # Block access to backup files
    location ~ \.(bak|backup|old|~)$ {
        deny all;
        return 404;
    }
    
    location / {
        proxy_pass http://localhost:5000;
    }
}
"""


# Example 8: SECURE - Security Hardening Checklist
"""
SECURITY HARDENING CHECKLIST:

Application Configuration:
✅ DEBUG = False in production
✅ SECRET_KEY from environment variable
✅ Error logging configured
✅ Generic error messages to users
✅ Disable unnecessary features
✅ Remove debug endpoints

Security Headers:
✅ X-Content-Type-Options: nosniff
✅ X-Frame-Options: DENY
✅ X-XSS-Protection: 1; mode=block
✅ Content-Security-Policy configured
✅ Strict-Transport-Security (HSTS)
✅ Referrer-Policy
✅ Permissions-Policy

CORS:
✅ Whitelist specific origins
✅ Don't use wildcard (*)
✅ Limit allowed methods
✅ Limit allowed headers

File Security:
✅ Block .env, .git files
✅ Disable directory listing
✅ Validate file uploads
✅ Use secure_filename()

Default Credentials:
✅ Change all default passwords
✅ Force password change on first login
✅ Use strong default passwords
✅ Document password requirements

Dependencies:
✅ Keep all packages updated
✅ Remove unused dependencies
✅ Pin dependency versions
✅ Scan for known vulnerabilities

Database:
✅ Use least privilege accounts
✅ Disable remote root access
✅ Change default ports if possible
✅ Enable query logging

Cloud Configuration:
✅ S3 buckets not public
✅ Security groups restrictive
✅ IAM principle of least privilege
✅ Enable CloudTrail logging

Monitoring:
✅ Log security events
✅ Monitor for errors
✅ Alert on suspicious activity
✅ Regular security scans
"""

# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
SECURITY MISCONFIGURATION PREVENTION:

Development:
✅ Use separate configs for dev/staging/prod
✅ Load secrets from environment variables
✅ Use .env.example (never commit .env)
✅ Document all configuration options
✅ Review default settings

Production:
✅ Disable debug mode
✅ Remove unnecessary features
✅ Configure all security headers
✅ Use restrictive CORS policy
✅ Generic error messages
✅ Block sensitive files

Deployment:
✅ Automated security scanning
✅ Configuration management (Ansible, Terraform)
✅ Infrastructure as Code
✅ Regular security audits
✅ Penetration testing

Monitoring:
✅ Log all configuration changes
✅ Monitor for misconfigurations
✅ Alert on security header failures
✅ Regular vulnerability scans
"""

# ============================================================================
# REAL-WORLD EXAMPLES
# ============================================================================

"""
REAL-WORLD SECURITY MISCONFIGURATION BREACHES:

1. Capital One (2019)
   - Misconfigured AWS WAF
   - 100 million customer records exposed
   - $80 million fine
   - Could have been prevented with proper config

2. Tesla (2018)
   - AWS S3 bucket public
   - Kubernetes admin console exposed
   - No password protection
   - Cryptocurrency mining malware installed

3. Uber (2016)
   - Private GitHub repo public
   - AWS credentials exposed
   - 57 million users compromised
   - $148 million settlement

4. Elasticsearch Clusters (2019-2020)
   - Default configuration exposed data
   - No authentication enabled
   - Billions of records exposed
   - Multiple companies affected

5. MongoDB Databases (2017-2018)
   - Default configuration allowed remote access
   - No authentication required
   - 200+ million records exposed
   - Ransomware attacks

6. Equifax (2017)
   - Unpatched Apache Struts
   - Default credentials on admin portal
   - 147 million records compromised
   - $700 million settlement

KEY LESSONS:
- Change ALL default credentials
- Disable debug mode in production
- Configure security headers
- Patch systems regularly
- Use configuration management
- Regular security audits
"""

# ============================================================================
# TESTING
# ============================================================================

def test_security_headers():
    """Test if security headers are configured"""
    print("\n=== Security Headers Test ===")
    
    headers_to_check = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'Referrer-Policy'
    ]
    
    print("Required security headers:")
    for header in headers_to_check:
        print(f"  - {header}")
    
    print("\n✅ Secure: All headers configured")
    print("❌ Vulnerable: Missing headers")


if __name__ == '__main__':
    print("OWASP A05:2021 - Security Misconfiguration Examples")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- Debug mode in production")
    print("- Verbose error messages")
    print("- Missing security headers")
    print("- Default credentials")
    print("- Overly permissive CORS")
    print("- Exposed configuration files")
    print("\nSecure implementations include:")
    print("✅ Proper production configuration")
    print("✅ Comprehensive security headers")
    print("✅ Restrictive CORS policy")
    print("✅ Generic error handling")
    print("✅ Protected sensitive files")
    
    test_security_headers()


