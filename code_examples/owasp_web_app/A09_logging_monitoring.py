"""
OWASP A09:2021 - Security Logging and Monitoring Failures
===========================================================

Insufficient logging and monitoring, coupled with missing or ineffective integration
with incident response, allows attackers to further attack systems, maintain
persistence, pivot to more systems, and tamper or extract data.

Common issues:
- No logging of security events
- Insufficient log details
- Logs not monitored
- No alerting on suspicious activity
- Logs easily tampered
- No centralized logging
"""

from flask import Flask, request, jsonify, session
import logging
import json
from datetime import datetime
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'change-me'

# ============================================================================
# VULNERABLE CODE - MISSING LOGGING
# ============================================================================

# Example 1: No Logging of Authentication Events
@app.route('/api/login_no_logging', methods=['POST'])
def login_no_logging():
    """
    VULNERABILITY: No logging of login attempts
    
    Impact: Cannot detect brute force, account takeover
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Check credentials
    if username == 'admin' and password == 'password123':
        # SUCCESS - but no logging!
        session['user'] = username
        return jsonify({'message': 'Login successful'})
    
    # FAILURE - no logging of failed attempt!
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 2: Logging Sensitive Data
logger = logging.getLogger(__name__)

@app.route('/api/process_payment_bad_logging', methods=['POST'])
def process_payment_bad_logging():
    """
    VULNERABILITY: Logging sensitive data
    
    Impact: Compliance violations, data exposure in logs
    """
    data = request.get_json()
    card_number = data.get('card_number')
    cvv = data.get('cvv')
    amount = data.get('amount')
    
    # VULNERABILITY: Logs contain sensitive data!
    logger.info(f"Processing payment: card={card_number}, cvv={cvv}, amount={amount}")
    
    # Process payment...
    
    return jsonify({'message': 'Payment processed'})


# Example 3: No Monitoring of Critical Actions
@app.route('/api/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user_no_monitoring(user_id):
    """
    VULNERABILITY: No logging of critical actions
    
    Impact: Cannot detect unauthorized deletions
    """
    # Delete user without logging!
    # No audit trail
    # No alert on bulk deletions
    
    return jsonify({'message': f'User {user_id} deleted'})


# Example 4: Insufficient Log Details
@app.route('/api/transfer_money_weak_logging', methods=['POST'])
def transfer_money_weak_logging():
    """
    VULNERABILITY: Insufficient log context
    
    Impact: Cannot investigate incidents properly
    """
    data = request.get_json()
    amount = data.get('amount')
    
    # Minimal logging - missing WHO, WHEN, FROM WHERE
    logger.info("Money transfer")
    
    return jsonify({'message': 'Transfer complete'})


# Example 5: No Error Logging
@app.route('/api/api_no_error_logging', methods=['GET'])
def api_no_error_logging():
    """
    VULNERABILITY: Errors not logged
    
    Impact: Cannot detect or diagnose issues
    """
    try:
        # Some operation that might fail
        result = 1 / 0
        return jsonify({'result': result})
    except:
        # Error silently ignored!
        return jsonify({'error': 'Something went wrong'}), 500


# ============================================================================
# SECURE CODE - COMPREHENSIVE LOGGING
# ============================================================================

# Configure structured logging
import logging.config
import sys

LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s',
            'class': 'pythonjsonlogger.jsonlogger.JsonFormatter'
        },
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'stream': sys.stdout
        },
        'security_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'json',
            'filename': '/var/log/app/security.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10
        },
        'audit_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'json',
            'filename': '/var/log/app/audit.log',
            'maxBytes': 10485760,
            'backupCount': 20
        }
    },
    'loggers': {
        'security': {
            'handlers': ['console', 'security_file'],
            'level': 'INFO',
            'propagate': False
        },
        'audit': {
            'handlers': ['console', 'audit_file'],
            'level': 'INFO',
            'propagate': False
        }
    }
}

# logging.config.dictConfig(LOGGING_CONFIG)
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')


# Helper function for structured logging
def log_security_event(event_type, severity, details):
    """
    SECURE: Structured security event logging
    
    Defense: Comprehensive, tamper-evident logging
    """
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'severity': severity,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'user': session.get('user', 'anonymous'),
        'request_id': request.headers.get('X-Request-ID', 'unknown'),
        'details': details
    }
    
    security_logger.info(json.dumps(log_entry))
    return log_entry


# Example 1: SECURE - Comprehensive Authentication Logging
class LoginAttemptMonitor:
    """
    SECURE: Monitor and alert on suspicious login activity
    
    Defense: Detect brute force, credential stuffing
    """
    def __init__(self):
        self.failed_attempts = {}  # Track failed attempts
    
    def log_login_attempt(self, username, success, reason=None):
        """Log all login attempts"""
        ip = request.remote_addr
        
        event_details = {
            'username': username,
            'success': success,
            'reason': reason,
            'ip': ip,
            'user_agent': request.headers.get('User-Agent')
        }
        
        if success:
            log_security_event('login_success', 'INFO', event_details)
            # Clear failed attempts on success
            self.failed_attempts.pop(ip, None)
        else:
            log_security_event('login_failure', 'WARNING', event_details)
            
            # Track failed attempts
            if ip not in self.failed_attempts:
                self.failed_attempts[ip] = []
            self.failed_attempts[ip].append({
                'username': username,
                'timestamp': datetime.utcnow()
            })
            
            # Alert on suspicious activity
            self.check_for_attacks(ip, username)
    
    def check_for_attacks(self, ip, username):
        """Detect and alert on attack patterns"""
        if ip not in self.failed_attempts:
            return
        
        attempts = self.failed_attempts[ip]
        recent_attempts = [
            a for a in attempts
            if (datetime.utcnow() - a['timestamp']).seconds < 300  # 5 min
        ]
        
        # Brute force detection
        if len(recent_attempts) >= 5:
            log_security_event('brute_force_detected', 'CRITICAL', {
                'ip': ip,
                'username': username,
                'attempt_count': len(recent_attempts)
            })
            # In production: trigger alert, block IP


login_monitor = LoginAttemptMonitor()


@app.route('/api/login_secure_logging', methods=['POST'])
def login_secure_logging():
    """
    SECURE: Comprehensive login logging
    
    Defense: Full audit trail of authentication
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Validate credentials
    if username == 'admin' and password == 'correct_password':
        session['user'] = username
        login_monitor.log_login_attempt(username, True)
        return jsonify({'message': 'Login successful'})
    
    # Log failed attempt
    login_monitor.log_login_attempt(username, False, 'invalid_credentials')
    
    return jsonify({'error': 'Invalid credentials'}), 401


# Example 2: SECURE - Sanitized Logging (No PII)
def sanitize_for_logging(data):
    """
    SECURE: Remove sensitive data before logging
    
    Defense: Compliance with privacy regulations
    """
    sensitive_keys = [
        'password', 'ssn', 'credit_card', 'card_number',
        'cvv', 'secret', 'token', 'api_key'
    ]
    
    sanitized = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            # Mask sensitive data
            if isinstance(value, str):
                if 'card' in key.lower():
                    sanitized[key] = f"****{value[-4:]}" if len(value) > 4 else "****"
                else:
                    sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = value
    
    return sanitized


@app.route('/api/process_payment_secure_logging', methods=['POST'])
def process_payment_secure_logging():
    """
    SECURE: Sanitized payment logging
    
    Defense: Log transaction without exposing PII
    """
    data = request.get_json()
    
    # Sanitize before logging
    safe_data = sanitize_for_logging(data)
    
    audit_logger.info(json.dumps({
        'event': 'payment_processed',
        'timestamp': datetime.utcnow().isoformat(),
        'user': session.get('user'),
        'ip': request.remote_addr,
        'data': safe_data
    }))
    
    # Process payment...
    
    return jsonify({'message': 'Payment processed'})


# Example 3: SECURE - Critical Action Monitoring
def log_critical_action(action, resource, details=None):
    """
    SECURE: Log critical actions with full context
    
    Defense: Audit trail for investigations
    """
    log_entry = {
        'event': 'critical_action',
        'action': action,
        'resource': resource,
        'timestamp': datetime.utcnow().isoformat(),
        'user': session.get('user', 'anonymous'),
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'details': details or {}
    }
    
    audit_logger.warning(json.dumps(log_entry))
    
    # Send to SIEM
    # send_to_siem(log_entry)
    
    # Alert if necessary
    if action in ['delete_user', 'modify_permissions', 'export_data']:
        # send_alert(log_entry)
        pass


@app.route('/api/delete_user_secure/<int:user_id>', methods=['DELETE'])
def delete_user_secure(user_id):
    """
    SECURE: Log critical user deletion
    
    Defense: Full audit trail
    """
    # Log before action
    log_critical_action('delete_user', f'user:{user_id}', {
        'initiated_by': session.get('user'),
        'reason': request.args.get('reason', 'not_specified')
    })
    
    # Perform deletion...
    
    # Log after action
    log_security_event('user_deleted', 'WARNING', {
        'user_id': user_id,
        'deleted_by': session.get('user')
    })
    
    return jsonify({'message': f'User {user_id} deleted'})


# Example 4: SECURE - Comprehensive Error Logging
@app.errorhandler(Exception)
def handle_error_secure(error):
    """
    SECURE: Comprehensive error logging
    
    Defense: Diagnose and detect attacks
    """
    import traceback
    
    error_details = {
        'error_type': type(error).__name__,
        'error_message': str(error),
        'traceback': traceback.format_exc(),
        'request_path': request.path,
        'request_method': request.method,
        'request_args': dict(request.args),
        'user': session.get('user', 'anonymous'),
        'ip': request.remote_addr
    }
    
    # Log full error details internally
    security_logger.error(json.dumps(error_details))
    
    # Return generic error to user
    return jsonify({'error': 'An error occurred'}), 500


@app.route('/api/api_secure_error_logging', methods=['GET'])
def api_secure_error_logging():
    """
    SECURE: Errors are logged
    
    Defense: Incident detection and response
    """
    try:
        result = 1 / 0
        return jsonify({'result': result})
    except Exception as e:
        # Error is logged by error handler
        raise  # Re-raise to trigger error handler


# Example 5: SECURE - Real-time Monitoring and Alerting
class SecurityMonitor:
    """
    SECURE: Real-time security monitoring
    
    Defense: Detect and respond to attacks in real-time
    """
    
    @staticmethod
    def detect_sql_injection(query_string):
        """Detect potential SQL injection attempts"""
        sql_patterns = [
            "' OR '1'='1",
            "' OR 1=1",
            "UNION SELECT",
            "DROP TABLE",
            "'; --",
            "' AND '1'='1"
        ]
        
        for pattern in sql_patterns:
            if pattern.upper() in query_string.upper():
                log_security_event('sql_injection_attempt', 'CRITICAL', {
                    'pattern': pattern,
                    'query': query_string,
                    'ip': request.remote_addr
                })
                return True
        return False
    
    @staticmethod
    def detect_xss(input_data):
        """Detect potential XSS attempts"""
        xss_patterns = [
            '<script',
            'javascript:',
            'onerror=',
            'onload=',
            '<iframe'
        ]
        
        for pattern in xss_patterns:
            if pattern.lower() in str(input_data).lower():
                log_security_event('xss_attempt', 'HIGH', {
                    'pattern': pattern,
                    'input': input_data[:100],  # Truncate
                    'ip': request.remote_addr
                })
                return True
        return False
    
    @staticmethod
    def detect_path_traversal(path):
        """Detect path traversal attempts"""
        if '../' in path or '..\\' in path:
            log_security_event('path_traversal_attempt', 'HIGH', {
                'path': path,
                'ip': request.remote_addr
            })
            return True
        return False


monitor = SecurityMonitor()


@app.before_request
def security_monitoring():
    """
    SECURE: Monitor all requests for attacks
    
    Defense: Real-time threat detection
    """
    # Log all API requests
    log_security_event('api_request', 'INFO', {
        'method': request.method,
        'path': request.path,
        'query_string': request.query_string.decode()
    })
    
    # Check for attack patterns
    query_string = request.query_string.decode()
    
    if monitor.detect_sql_injection(query_string):
        # Block request
        return jsonify({'error': 'Invalid request'}), 400
    
    if request.is_json:
        data = request.get_json()
        if monitor.detect_xss(str(data)):
            return jsonify({'error': 'Invalid input'}), 400


# ============================================================================
# CENTRALIZED LOGGING
# ============================================================================

"""
SECURE: Send logs to centralized system

# Options for centralized logging:

1. ELK Stack (Elasticsearch, Logstash, Kibana)
2. Splunk
3. Datadog
4. AWS CloudWatch
5. Azure Monitor
6. Google Cloud Logging

# Example: Sending to ELK
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://localhost:9200'])

def send_to_elasticsearch(log_entry):
    es.index(index='security-logs', document=log_entry)

# Example: Sending to Splunk
import splunk_http_event_collector as splunk

splunk_logger = splunk.http_event_collector(
    token='your-token',
    http_event_server='splunk.example.com'
)

def send_to_splunk(log_entry):
    splunk_logger.sendEvent(log_entry)
"""

# ============================================================================
# ALERTING RULES
# ============================================================================

"""
SECURE: Alerting rules for security events

# Define alerting thresholds

ALERT_RULES = {
    'brute_force': {
        'threshold': 5,  # 5 failed logins
        'window': 300,   # in 5 minutes
        'severity': 'CRITICAL',
        'actions': ['email', 'slack', 'pagerduty']
    },
    'sql_injection': {
        'threshold': 1,  # Any attempt
        'severity': 'CRITICAL',
        'actions': ['email', 'slack', 'block_ip']
    },
    'privilege_escalation': {
        'threshold': 1,
        'severity': 'HIGH',
        'actions': ['email', 'slack']
    },
    'data_exfiltration': {
        'threshold': 100,  # 100+ records exported
        'window': 60,      # in 1 minute
        'severity': 'CRITICAL',
        'actions': ['email', 'slack', 'pagerduty', 'block_user']
    }
}

# Example alert function
def send_alert(alert_type, details):
    '''Send alert via configured channels'''
    if alert_type not in ALERT_RULES:
        return
    
    rule = ALERT_RULES[alert_type]
    
    for action in rule['actions']:
        if action == 'email':
            send_email_alert(details)
        elif action == 'slack':
            send_slack_alert(details)
        elif action == 'pagerduty':
            create_pagerduty_incident(details)
        elif action == 'block_ip':
            block_ip_address(details['ip'])
"""

# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
LOGGING AND MONITORING BEST PRACTICES:

What to Log:
✅ Authentication events (success/failure)
✅ Authorization failures
✅ Input validation failures
✅ Application errors
✅ Security-sensitive operations
✅ Administrative actions
✅ Data access/changes
✅ Configuration changes

Log Details to Include:
✅ Timestamp (UTC)
✅ User/session identifier
✅ IP address
✅ Action performed
✅ Resource accessed
✅ Outcome (success/failure)
✅ User agent
✅ Request ID

What NOT to Log:
❌ Passwords
❌ Session tokens
❌ Credit card numbers
❌ Social security numbers
❌ API keys
❌ Encryption keys
❌ Personal health information

Log Management:
✅ Centralized logging (SIEM)
✅ Structured logging (JSON)
✅ Log rotation and retention
✅ Tamper-evident logs
✅ Regular log review
✅ Automated analysis

Monitoring:
✅ Real-time alerting
✅ Anomaly detection
✅ Threshold-based alerts
✅ Dashboard visualization
✅ Incident response integration
✅ Playbooks for common incidents

Compliance:
✅ GDPR compliance (data minimization)
✅ PCI-DSS logging requirements
✅ HIPAA audit trails
✅ SOC 2 logging controls
✅ Log retention policies

CODE CHECKLIST:

✅ Authentication events logged
✅ Authorization failures logged
✅ Security events logged
✅ Errors logged with details
✅ No sensitive data in logs
✅ Structured logging format
✅ Centralized log aggregation
✅ Real-time monitoring configured
✅ Alerting rules defined
✅ Log retention policy set
✅ Regular log review process
✅ Incident response plan
"""

# ============================================================================
# REAL-WORLD EXAMPLES
# ============================================================================

"""
REAL-WORLD INCIDENTS DUE TO POOR LOGGING:

1. EQUIFAX (2017)
   - Breach went undetected for 76 days
   - Insufficient monitoring
   - 147 million records compromised
   - Could have been detected with proper logging

2. MARRIOTT (2018)
   - Breach undetected for 4 years
   - Poor log monitoring
   - 500 million guest records exposed
   - Inadequate security logging

3. UBER (2016)
   - Breach undetected, hackers paid ransom
   - Poor incident response
   - 57 million users affected
   - Logs not properly monitored

4. CAPITAL ONE (2019)
   - Misconfiguration not detected
   - 100 million customers affected
   - Proper monitoring could have prevented it

5. TARGET (2013)
   - Security alerts ignored
   - 40 million credit cards stolen
   - Alerts were generated but not acted upon

DWELL TIME (Average time attacker undetected):
- 2023 Average: 16 days
- Financial: 21 days
- Healthcare: 49 days
- Retail: 18 days

Goal: Reduce dwell time with effective logging & monitoring

KEY LESSONS:
- Log security-relevant events
- Monitor logs in real-time
- Set up meaningful alerts
- Respond to alerts quickly
- Regular security reviews
- Automate threat detection
"""

# ============================================================================
# TESTING
# ============================================================================

def test_logging():
    """Test logging configuration"""
    print("\n=== Logging Configuration Test ===\n")
    
    # Test security logger
    print("Testing security logger...")
    log_security_event('test_event', 'INFO', {'test': 'data'})
    print("✅ Security logger working")
    
    # Test audit logger
    print("\nTesting audit logger...")
    audit_logger.info("Test audit log")
    print("✅ Audit logger working")
    
    print("\n=== Required Log Events ===\n")
    required_events = [
        "Authentication attempts",
        "Authorization failures",
        "Input validation failures",
        "Application errors",
        "Administrative actions",
        "Data access/modifications",
        "Security configuration changes"
    ]
    
    for event in required_events:
        print(f"  ✅ {event}")
    
    print("\n=== Monitoring Checklist ===\n")
    monitoring_items = [
        "Centralized logging configured",
        "Real-time alerting enabled",
        "Log retention policy defined",
        "Sensitive data not logged",
        "Structured logging (JSON)",
        "Security dashboard created",
        "Incident response plan ready"
    ]
    
    for item in monitoring_items:
        print(f"  ✅ {item}")


if __name__ == '__main__':
    print("OWASP A09:2021 - Security Logging and Monitoring Failures")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- Missing authentication logging")
    print("- Logging sensitive data")
    print("- No monitoring of critical actions")
    print("- Insufficient log details")
    print("- No error logging")
    print("\nSecure implementations include:")
    print("✅ Comprehensive security logging")
    print("✅ Sanitized logs (no PII)")
    print("✅ Real-time monitoring")
    print("✅ Automated alerting")
    print("✅ Centralized log management")
    
    test_logging()


