"""
OWASP LLM Top 10 - LLM07: Insecure Plugin Design

Demonstration of security risks in LLM plugins and extensions.

Insecure Plugin Design occurs when:
- Plugins accept unvalidated inputs from LLM
- Plugins have excessive permissions
- Plugins don't validate LLM outputs
- Plugins lack proper authorization

CRITICAL FOR PAYPAL: Payment plugins must validate all inputs and
require explicit user authorization before executing transactions.
"""

def demonstrate_concept():
    """Demonstrate insecure plugin design concepts"""
    
    print("=" * 70)
    print("OWASP LLM07: INSECURE PLUGIN DESIGN")
    print("=" * 70)
    
    print("""
    VULNERABILITY: Insecure LLM Plugins
    
    Attack Scenarios:
    
    1. UNVALIDATED PLUGIN INPUTS
       Vulnerable Plugin:
       ```python
       def send_money(to_account, amount):
           # NO INPUT VALIDATION!
           bank_api.transfer(to_account, amount)
       ```
       
       Attack: LLM generates malicious parameters
       - Negative amounts (withdraw instead of deposit)
       - SQL injection in account parameter
       - Excessive amounts
    
    2. EXCESSIVE PLUGIN PERMISSIONS
       Vulnerable: Plugin can access all user data
       ```python
       class EmailPlugin:
           def send_email(self, to, subject, body):
               # Can email ANYONE, no restrictions!
               smtp.send(to, subject, body)
       ```
       
       Attack: Plugin sends sensitive data to attacker
    
    3. NO USER CONFIRMATION
       Vulnerable: Plugin executes immediately
       ```python
       def delete_account(account_id):
           # NO CONFIRMATION!
           db.delete(f"DELETE FROM accounts WHERE id={account_id}")
       ```
       
       Attack: LLM told to delete account, does it immediately
    
    4. MISSING AUTHORIZATION CHECKS
       Vulnerable: Plugin doesn't verify ownership
       ```python
       def view_transactions(account_id):
           # NO AUTHORIZATION CHECK!
           return db.query(f"SELECT * FROM transactions WHERE account_id={account_id}")
       ```
       
       Attack: Access other users' transaction history
    
    SECURE PLUGIN DESIGN:
    
    1. INPUT VALIDATION
       ```python
       def send_money(to_account: str, amount: float, user_id: str) -> dict:
           # Validate amount
           if amount <= 0 or amount > MAX_TRANSFER:
               raise ValueError("Invalid amount")
           
           # Validate account format
           if not re.match(r'^[A-Z0-9]{10}$', to_account):
               raise ValueError("Invalid account format")
           
           # Validate user owns source account
           if not user_owns_account(user_id):
               raise PermissionError("Unauthorized")
           
           # Return confirmation request
           return {
               "status": "pending_confirmation",
               "action": "transfer",
               "params": {"to": to_account, "amount": amount},
               "requires_mfa": True
           }
       ```
    
    2. LEAST PRIVILEGE
       ```python
       class SecureEmailPlugin:
           def __init__(self, allowed_domains: List[str]):
               self.allowed_domains = allowed_domains  # Whitelist
           
           def send_email(self, to: str, subject: str, body: str) -> dict:
               # Check recipient domain
               domain = to.split('@')[1]
               if domain not in self.allowed_domains:
                   raise PermissionError(f"Cannot email {domain}")
               
               # Scan body for sensitive data
               if contains_pii(body):
                   raise SecurityError("PII detected in email body")
               
               # Require confirmation
               return {"status": "pending_confirmation"}
       ```
    
    3. USER CONFIRMATION REQUIRED
       ```python
       class SecureActionPlugin:
           def execute_action(self, action: str, params: dict) -> dict:
               # Generate confirmation token
               token = generate_confirmation_token(action, params)
               
               # Return to user for confirmation
               return {
                   "status": "awaiting_confirmation",
                   "message": f"Confirm: {action} with {params}",
                   "confirmation_token": token,
                   "expires_in": 300  # 5 minutes
               }
           
           def confirm_action(self, token: str, user_confirmation: bool) -> dict:
               if not user_confirmation:
                   return {"status": "cancelled"}
               
               # Verify token
               action, params = verify_token(token)
               
               # Execute
               return execute_with_audit(action, params)
       ```
    
    4. AUTHORIZATION ENFORCEMENT
       ```python
       def view_transactions(account_id: str, user_id: str) -> dict:
           # Verify user owns account
           if not user_owns_account(user_id, account_id):
               raise PermissionError("Access denied")
           
           # Verify user has permission
           if not has_permission(user_id, "view_transactions"):
               raise PermissionError("Insufficient permissions")
           
           # Audit log
           log_access(user_id, "view_transactions", account_id)
           
           # Return data
           return get_transactions(account_id)
       ```
    
    PLUGIN SECURITY CHECKLIST:
    
    Input Validation:
    - [ ] Validate all parameters from LLM
    - [ ] Type checking and format validation
    - [ ] Range checks (min/max values)
    - [ ] Sanitize for injection attacks
    - [ ] Length limits enforced
    
    Authorization:
    - [ ] Verify user identity
    - [ ] Check user permissions
    - [ ] Validate resource ownership
    - [ ] Audit log all actions
    - [ ] Rate limiting per user
    
    Confirmation:
    - [ ] User confirmation for sensitive actions
    - [ ] Display clear action description
    - [ ] Time-limited confirmation tokens
    - [ ] MFA for high-risk operations
    - [ ] Cannot be auto-confirmed
    
    Least Privilege:
    - [ ] Minimal permissions granted
    - [ ] Whitelist allowed operations
    - [ ] Whitelist allowed destinations
    - [ ] Read-only by default
    - [ ] Escalation for write operations
    
    Output Validation:
    - [ ] Scan output for PII
    - [ ] Validate response format
    - [ ] Error handling (no stack traces)
    - [ ] Rate limiting on data retrieval
    - [ ] Audit logging
    
    PAYPAL PLUGIN REQUIREMENTS:
    ✓ ALL payment plugins require MFA
    ✓ Transaction confirmation UI mandatory
    ✓ Amount limits enforced
    ✓ Recipient validation
    ✓ Fraud detection checks
    ✓ Audit trail for compliance
    
    SECURE PLUGIN ARCHITECTURE:
    
    ```
    LLM generates intent: "Send $100 to Alice"
        ↓
    Plugin receives: {"action": "transfer", "to": "alice@example.com", "amount": 100}
        ↓
    [Input Validation Layer]
        ↓
    [Authorization Check]
        ↓
    [Generate Confirmation Request]
        ↓
    User confirms on UI (not via LLM)
        ↓
    [Verify Confirmation Token]
        ↓
    [MFA Challenge]
        ↓
    [Execute Transaction]
        ↓
    [Audit Log]
    ```
    
    REAL-WORLD INCIDENTS:
    - ChatGPT Plugin Vulnerabilities (2023): Plugins lacked input validation
    - Zapier AI Actions: Excessive permissions discovered
    - Google Bard Extensions: Privacy concerns over data access
    
    TESTING PLUGINS:
    - Fuzz testing with malicious inputs
    - Authorization bypass attempts
    - Prompt injection to manipulate parameters
    - Rate limit testing
    - Data exfiltration attempts
    """)
    
    print("\n" + "=" * 70)
    print("KEY TAKEAWAY")
    print("=" * 70)
    print("""
    Insecure plugins are a major attack vector for LLM applications.
    
    Defense requires:
    - Validate ALL plugin inputs
    - Enforce authorization checks
    - Require user confirmation
    - Apply least privilege
    - Audit all actions
    
    For PayPal: Payment plugins MUST have confirmation + MFA.
    """)


if __name__ == "__main__":
    demonstrate_concept()

