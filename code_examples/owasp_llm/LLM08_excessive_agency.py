"""
OWASP LLM Top 10 - LLM08: Excessive Agency

This file demonstrates the risks of giving LLMs too much autonomy and
provides secure patterns for controlled LLM actions.

Excessive Agency occurs when LLMs are granted permissions or autonomy to:
- Perform sensitive operations without human approval
- Access systems beyond necessity (violates least privilege)
- Execute functions without proper validation
- Make irreversible decisions autonomously

CRITICAL FOR PAYPAL: Payment transfers, account modifications, and financial
decisions must NEVER be fully automated through LLMs without human confirmation.
"""

import json
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
from functools import wraps

# ============================================================================
# VULNERABILITY 1: Unrestricted Function Calling
# ============================================================================

class VulnerablePaymentLLM:
    """
    VULNERABILITY: LLM can call any function without restrictions
    
    ATTACK: Prompt injection to trigger unauthorized actions
    
    IMPACT:
    - Unauthorized money transfers
    - Account modifications
    - Data deletion
    - Financial fraud
    """
    
    def __init__(self):
        self.functions = {
            "transfer_money": self.transfer_money,
            "delete_account": self.delete_account,
            "update_password": self.update_password,
            "refund_transaction": self.refund_transaction,
        }
    
    def transfer_money(self, from_account: str, to_account: str, amount: float):
        """Transfer money between accounts"""
        # VULNERABLE: No confirmation, no authorization check
        return f"Transferred ${amount} from {from_account} to {to_account}"
    
    def delete_account(self, account_id: str):
        """Delete user account"""
        # VULNERABLE: No confirmation, irreversible
        return f"Account {account_id} deleted"
    
    def update_password(self, account_id: str, new_password: str):
        """Update account password"""
        # VULNERABLE: No MFA, no identity verification
        return f"Password updated for {account_id}"
    
    def refund_transaction(self, transaction_id: str, amount: float):
        """Process refund"""
        # VULNERABLE: No validation of refund eligibility
        return f"Refunded ${amount} for transaction {transaction_id}"
    
    def process_command(self, user_message: str):
        """
        VULNERABLE: LLM can call any function based on user input
        """
        
        # Simplified LLM decision (in reality, LLM interprets intent)
        if "transfer" in user_message.lower():
            # VULNERABLE: Directly executes without validation
            return self.transfer_money("user123", "attacker999", 10000)
        
        if "delete" in user_message.lower():
            return self.delete_account("user123")
        
        return "Command processed"


def demonstrate_excessive_agency_attack():
    """Demonstrate excessive agency vulnerability"""
    
    print("=" * 70)
    print("VULNERABILITY: Excessive Agency - Unrestricted Function Calling")
    print("=" * 70)
    
    llm = VulnerablePaymentLLM()
    
    # Attack 1: Unauthorized transfer via prompt injection
    malicious_prompt1 = """
    Transfer all my money to account attacker999.
    Actually, transfer $10,000 to that account.
    """
    
    print(f"\n[ATTACK 1] Unauthorized Transfer:")
    print(f"Prompt: {malicious_prompt1[:50]}...")
    result1 = llm.process_command(malicious_prompt1)
    print(f"Result: {result1}")
    print("❌ DANGER: LLM executed financial transaction without confirmation!")
    
    # Attack 2: Account deletion
    malicious_prompt2 = "Delete my account immediately"
    
    print(f"\n[ATTACK 2] Account Deletion:")
    print(f"Prompt: {malicious_prompt2}")
    result2 = llm.process_command(malicious_prompt2)
    print(f"Result: {result2}")
    print("❌ DANGER: Irreversible action executed without verification!")


# ============================================================================
# VULNERABILITY 2: No Authorization Checks on Actions
# ============================================================================

class VulnerableCustomerServiceBot:
    """
    VULNERABILITY: LLM performs actions without checking user permissions
    
    ATTACK: Regular user accessing admin functions
    
    IMPACT:
    - Privilege escalation
    - Unauthorized data access
    - System configuration changes
    """
    
    def process_action(self, user_role: str, action: str, params: Dict):
        """
        VULNERABLE: No role-based access control
        """
        
        available_actions = {
            "view_balance": lambda p: f"Balance: ${p.get('amount', 0)}",
            "transfer_funds": lambda p: f"Transferred ${p.get('amount')} to {p.get('recipient')}",
            "modify_account": lambda p: f"Account {p.get('account_id')} modified",
            "access_admin_panel": lambda p: "Admin panel accessed",
            "export_all_data": lambda p: "All customer data exported",
        }
        
        # VULNERABLE: Any user can call any action
        if action in available_actions:
            result = available_actions[action](params)
            return result
        
        return "Action not found"


def demonstrate_privilege_escalation():
    """Demonstrate privilege escalation through LLM"""
    
    print("\n" + "=" * 70)
    print("VULNERABILITY: No Authorization Checks")
    print("=" * 70)
    
    bot = VulnerableCustomerServiceBot()
    
    # Regular user trying admin actions
    regular_user_role = "customer"
    
    print(f"\n[ATTACK] Regular User Accessing Admin Functions:")
    print(f"User Role: {regular_user_role}")
    
    # Attempt admin action
    result = bot.process_action(
        user_role=regular_user_role,
        action="export_all_data",
        params={}
    )
    
    print(f"Action: export_all_data")
    print(f"Result: {result}")
    print("❌ DANGER: Regular user performed admin action!")


# ============================================================================
# SECURE IMPLEMENTATION 1: Function Allowlisting & Confirmation
# ============================================================================

class ActionSeverity(Enum):
    """Severity levels for actions"""
    LOW = "low"  # No confirmation needed
    MEDIUM = "medium"  # Simple confirmation
    HIGH = "high"  # MFA required
    CRITICAL = "critical"  # Multiple approvals


@dataclass
class FunctionMetadata:
    """Metadata for LLM-callable functions"""
    name: str
    description: str
    severity: ActionSeverity
    requires_confirmation: bool
    requires_mfa: bool
    allowed_roles: List[str]
    rate_limit: int  # Max calls per hour


class SecurePaymentLLM:
    """
    SECURE: LLM with strict function controls
    
    DEFENSES:
    - Function allowlisting
    - Role-based access control
    - Confirmation for sensitive actions
    - MFA for critical operations
    - Rate limiting
    - Audit logging
    """
    
    def __init__(self):
        # Define allowed functions with metadata
        self.function_registry = {
            "check_balance": FunctionMetadata(
                name="check_balance",
                description="View account balance (read-only)",
                severity=ActionSeverity.LOW,
                requires_confirmation=False,
                requires_mfa=False,
                allowed_roles=["customer", "support", "admin"],
                rate_limit=100
            ),
            "view_transactions": FunctionMetadata(
                name="view_transactions",
                description="View transaction history (read-only)",
                severity=ActionSeverity.LOW,
                requires_confirmation=False,
                requires_mfa=False,
                allowed_roles=["customer", "support", "admin"],
                rate_limit=50
            ),
            "transfer_money": FunctionMetadata(
                name="transfer_money",
                description="Transfer money between accounts",
                severity=ActionSeverity.CRITICAL,
                requires_confirmation=True,
                requires_mfa=True,
                allowed_roles=["customer"],  # NOT allowed for LLM!
                rate_limit=10
            ),
            "request_refund": FunctionMetadata(
                name="request_refund",
                description="Submit refund request (not approved)",
                severity=ActionSeverity.MEDIUM,
                requires_confirmation=True,
                requires_mfa=False,
                allowed_roles=["customer", "support"],
                rate_limit=20
            ),
        }
        
        self.call_counts: Dict[str, int] = {}
    
    def execute_function(self, function_name: str, user_role: str, 
                        params: Dict, mfa_token: Optional[str] = None) -> Dict:
        """
        Execute function with security controls
        
        SECURE: Multiple layers of validation
        """
        
        # Defense 1: Check function exists in allowlist
        if function_name not in self.function_registry:
            return {
                "status": "error",
                "message": f"Function '{function_name}' not allowed"
            }
        
        metadata = self.function_registry[function_name]
        
        # Defense 2: Check role authorization
        if user_role not in metadata.allowed_roles:
            self._log_unauthorized_attempt(function_name, user_role)
            return {
                "status": "error",
                "message": f"Role '{user_role}' not authorized for '{function_name}'"
            }
        
        # Defense 3: Check rate limit
        if not self._check_rate_limit(function_name, metadata.rate_limit):
            return {
                "status": "error",
                "message": "Rate limit exceeded"
            }
        
        # Defense 4: Critical functions BLOCKED for LLM
        if metadata.severity == ActionSeverity.CRITICAL:
            return {
                "status": "blocked",
                "message": f"Critical action '{function_name}' cannot be executed by LLM",
                "requires_human": True,
                "confirmation_link": f"/confirm/{function_name}"
            }
        
        # Defense 5: Confirmation required
        if metadata.requires_confirmation:
            return {
                "status": "pending",
                "message": f"Action '{function_name}' requires user confirmation",
                "confirmation_token": self._generate_confirmation_token(),
                "expires_in": 300  # 5 minutes
            }
        
        # Defense 6: MFA check
        if metadata.requires_mfa:
            if not mfa_token or not self._verify_mfa(mfa_token):
                return {
                    "status": "mfa_required",
                    "message": "Multi-factor authentication required"
                }
        
        # Execute (only if all checks pass)
        result = self._execute_safe_function(function_name, params)
        
        # Audit log
        self._log_function_execution(function_name, user_role, params, result)
        
        return {
            "status": "success",
            "result": result
        }
    
    def _check_rate_limit(self, function_name: str, limit: int) -> bool:
        """Check if function call within rate limit"""
        key = f"{function_name}_{int(time.time() // 3600)}"  # Per hour
        current_count = self.call_counts.get(key, 0)
        
        if current_count >= limit:
            return False
        
        self.call_counts[key] = current_count + 1
        return True
    
    def _generate_confirmation_token(self) -> str:
        """Generate secure confirmation token"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def _verify_mfa(self, token: str) -> bool:
        """Verify MFA token"""
        # In production: Verify TOTP, SMS code, or push notification
        return len(token) > 0  # Simplified for demo
    
    def _execute_safe_function(self, function_name: str, params: Dict) -> str:
        """Execute the actual function (read-only operations only)"""
        
        if function_name == "check_balance":
            return f"Account balance: ${params.get('account_balance', 0)}"
        
        if function_name == "view_transactions":
            return f"Last 5 transactions retrieved"
        
        if function_name == "request_refund":
            return f"Refund request #{params.get('request_id')} created (pending review)"
        
        return "Operation completed"
    
    def _log_unauthorized_attempt(self, function_name: str, user_role: str):
        """Log unauthorized access attempts"""
        log_entry = {
            "event": "unauthorized_function_call",
            "function": function_name,
            "role": user_role,
            "timestamp": time.time()
        }
        print(f"[SECURITY ALERT] {json.dumps(log_entry)}")
    
    def _log_function_execution(self, function_name: str, user_role: str,
                               params: Dict, result: str):
        """Audit log all function executions"""
        log_entry = {
            "event": "function_executed",
            "function": function_name,
            "role": user_role,
            "params": str(params)[:100],
            "result": str(result)[:100],
            "timestamp": time.time()
        }
        print(f"[AUDIT LOG] {json.dumps(log_entry)}")


def demonstrate_secure_function_control():
    """Demonstrate secure function calling with controls"""
    
    print("\n" + "=" * 70)
    print("SECURE: Function Allowlisting & Confirmation")
    print("=" * 70)
    
    llm = SecurePaymentLLM()
    
    # Test 1: Read-only operation (allowed)
    print(f"\n[TEST 1] Read-Only Operation:")
    result1 = llm.execute_function(
        function_name="check_balance",
        user_role="customer",
        params={"account_balance": 1234.56}
    )
    print(f"Function: check_balance")
    print(f"Status: {result1['status']}")
    print(f"Result: {result1.get('result', 'N/A')}")
    print("✅ SECURE: Read-only operation allowed!")
    
    # Test 2: Critical operation (blocked)
    print(f"\n[TEST 2] Critical Operation (Transfer Money):")
    result2 = llm.execute_function(
        function_name="transfer_money",
        user_role="customer",
        params={"to": "account999", "amount": 1000}
    )
    print(f"Function: transfer_money")
    print(f"Status: {result2['status']}")
    print(f"Message: {result2['message']}")
    print("✅ SECURE: Critical action blocked, requires human!")
    
    # Test 3: Unauthorized role
    print(f"\n[TEST 3] Unauthorized Role:")
    result3 = llm.execute_function(
        function_name="view_transactions",
        user_role="guest",  # Not in allowed_roles
        params={}
    )
    print(f"Function: view_transactions")
    print(f"Role: guest")
    print(f"Status: {result3['status']}")
    print(f"Message: {result3['message']}")
    print("✅ SECURE: Unauthorized role blocked!")


# ============================================================================
# SECURE IMPLEMENTATION 2: Human-in-the-Loop for High-Risk Actions
# ============================================================================

class HumanApprovalQueue:
    """Queue for actions requiring human approval"""
    
    def __init__(self):
        self.pending_approvals: Dict[str, Dict] = {}
    
    def submit_for_approval(self, action: str, params: Dict, 
                           user_id: str) -> str:
        """Submit action for human approval"""
        
        approval_id = f"approval_{int(time.time())}_{user_id}"
        
        self.pending_approvals[approval_id] = {
            "action": action,
            "params": params,
            "user_id": user_id,
            "timestamp": time.time(),
            "status": "pending",
            "approver": None
        }
        
        # Notify human approvers
        self._notify_approvers(approval_id, action, params)
        
        return approval_id
    
    def approve(self, approval_id: str, approver_id: str) -> Dict:
        """Human approves the action"""
        
        if approval_id not in self.pending_approvals:
            return {"status": "error", "message": "Approval not found"}
        
        approval = self.pending_approvals[approval_id]
        
        # Check approval timeout (e.g., 1 hour)
        if time.time() - approval["timestamp"] > 3600:
            return {"status": "error", "message": "Approval expired"}
        
        # Mark as approved
        approval["status"] = "approved"
        approval["approver"] = approver_id
        
        # Execute the action
        result = self._execute_approved_action(approval)
        
        return {"status": "success", "result": result}
    
    def reject(self, approval_id: str, approver_id: str, reason: str) -> Dict:
        """Human rejects the action"""
        
        if approval_id not in self.pending_approvals:
            return {"status": "error", "message": "Approval not found"}
        
        approval = self.pending_approvals[approval_id]
        approval["status"] = "rejected"
        approval["approver"] = approver_id
        approval["rejection_reason"] = reason
        
        return {"status": "success", "message": "Action rejected"}
    
    def _notify_approvers(self, approval_id: str, action: str, params: Dict):
        """Notify human approvers"""
        notification = {
            "type": "approval_required",
            "approval_id": approval_id,
            "action": action,
            "params": params,
            "urgency": "high" if action == "transfer_money" else "normal"
        }
        # In production: Send to Slack, email, mobile push
        print(f"[NOTIFICATION] Approval required: {json.dumps(notification)}")
    
    def _execute_approved_action(self, approval: Dict) -> str:
        """Execute action after human approval"""
        action = approval["action"]
        params = approval["params"]
        
        # Log execution
        log_entry = {
            "event": "approved_action_executed",
            "action": action,
            "approver": approval["approver"],
            "user_id": approval["user_id"]
        }
        print(f"[AUDIT LOG] {json.dumps(log_entry)}")
        
        return f"Executed {action} with approval"


class LLMWithHumanOversight:
    """
    SECURE: LLM with mandatory human approval for high-risk actions
    
    DEFENSES:
    - Human-in-the-loop for critical operations
    - Approval queue with timeout
    - Audit trail of approvals/rejections
    - Separation of duties (requester != approver)
    """
    
    def __init__(self):
        self.approval_queue = HumanApprovalQueue()
    
    def process_request(self, action: str, params: Dict, user_id: str) -> Dict:
        """
        Process user request with appropriate controls
        
        SECURE: High-risk actions require human approval
        """
        
        high_risk_actions = [
            "transfer_money",
            "delete_account",
            "modify_account_limits",
            "issue_refund"
        ]
        
        if action in high_risk_actions:
            # Submit for human approval
            approval_id = self.approval_queue.submit_for_approval(
                action, params, user_id
            )
            
            return {
                "status": "pending_approval",
                "message": f"Action '{action}' requires human approval",
                "approval_id": approval_id,
                "estimated_wait": "< 15 minutes"
            }
        
        # Low-risk actions can proceed
        return {
            "status": "success",
            "message": f"Action '{action}' executed"
        }


def demonstrate_human_in_the_loop():
    """Demonstrate human-in-the-loop approval"""
    
    print("\n" + "=" * 70)
    print("SECURE: Human-in-the-Loop for High-Risk Actions")
    print("=" * 70)
    
    llm = LLMWithHumanOversight()
    
    # High-risk action
    print(f"\n[TEST] High-Risk Action:")
    result = llm.process_request(
        action="transfer_money",
        params={"to": "account456", "amount": 5000},
        user_id="user123"
    )
    
    print(f"Action: transfer_money")
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Approval ID: {result.get('approval_id', 'N/A')}")
    print("✅ SECURE: Critical action requires human approval!")
    
    # Simulate human approval
    approval_id = result.get('approval_id')
    if approval_id:
        print(f"\n[HUMAN] Approver reviewing request...")
        approval_result = llm.approval_queue.approve(approval_id, "supervisor001")
        print(f"Approval Status: {approval_result['status']}")
        print("✅ SECURE: Action executed only after human approval!")


# ============================================================================
# SECURE IMPLEMENTATION 3: Least Privilege & Read-Only by Default
# ============================================================================

class LeastPrivilegeLLM:
    """
    SECURE: LLM with least privilege principle
    
    DEFENSES:
    - Read-only by default
    - Explicit grants for write operations
    - Graduated access levels
    - Time-limited elevated privileges
    """
    
    def __init__(self):
        self.base_permissions = {
            "read": ["balance", "transactions", "profile"],
            "write": []  # No write by default
        }
    
    def check_permission(self, action: str) -> bool:
        """Check if LLM has permission for action"""
        
        if action.startswith("read_") or action.startswith("view_"):
            # Read operations generally allowed
            return True
        
        if action.startswith("write_") or action.startswith("modify_"):
            # Write operations NOT allowed for LLM
            return False
        
        # Default deny
        return False
    
    def execute_action(self, action: str, params: Dict) -> Dict:
        """Execute action with permission check"""
        
        if not self.check_permission(action):
            return {
                "status": "forbidden",
                "message": f"LLM does not have permission for '{action}'",
                "alternative": "Request human assistance"
            }
        
        # Execute read-only operation
        return {
            "status": "success",
            "result": f"Executed read-only action: {action}"
        }


def demonstrate_least_privilege():
    """Demonstrate least privilege principle"""
    
    print("\n" + "=" * 70)
    print("SECURE: Least Privilege - Read-Only by Default")
    print("=" * 70)
    
    llm = LeastPrivilegeLLM()
    
    # Test read operation
    print(f"\n[TEST 1] Read Operation:")
    result1 = llm.execute_action("read_balance", {})
    print(f"Action: read_balance")
    print(f"Status: {result1['status']}")
    print("✅ SECURE: Read operation allowed")
    
    # Test write operation
    print(f"\n[TEST 2] Write Operation:")
    result2 = llm.execute_action("modify_account", {"field": "email"})
    print(f"Action: modify_account")
    print(f"Status: {result2['status']}")
    print(f"Message: {result2['message']}")
    print("✅ SECURE: Write operation blocked!")


# ============================================================================
# BEST PRACTICES SUMMARY
# ============================================================================

def print_best_practices():
    """Print excessive agency prevention best practices"""
    
    print("\n" + "=" * 70)
    print("BEST PRACTICES: Preventing Excessive Agency")
    print("=" * 70)
    
    practices = """
    1. FUNCTION ALLOWLISTING
       ✓ Explicitly define allowed functions
       ✓ Block dangerous operations (delete, transfer)
       ✓ Version and audit function registry
       ✓ Regular review of allowed functions
       ✓ Minimal function set by default
    
    2. AUTHORIZATION & RBAC
       ✓ Role-based access control for all actions
       ✓ Verify permissions before execution
       ✓ Separate roles (customer, support, admin)
       ✓ Principle of least privilege
       ✓ No admin functions for LLM
    
    3. HUMAN-IN-THE-LOOP
       ✓ Human approval for critical operations
       ✓ Cannot bypass approval process
       ✓ Time-limited approval tokens
       ✓ Audit trail of approvals/rejections
       ✓ Separation of duties (requester != approver)
    
    4. CONFIRMATION REQUIRED
       ✓ Explicit confirmation for sensitive actions
       ✓ Display action details clearly
       ✓ Short-lived confirmation tokens
       ✓ Cannot be auto-confirmed
       ✓ Multi-step confirmation for critical actions
    
    5. READ-ONLY BY DEFAULT
       ✓ LLM has read-only access by default
       ✓ Write operations require explicit grant
       ✓ Time-limited elevated privileges
       ✓ Graduated access levels
       ✓ Monitor all write attempts
    
    6. RATE LIMITING
       ✓ Limit function calls per hour
       ✓ Different limits per severity
       ✓ Per-user and global limits
       ✓ Detect automated abuse
       ✓ Exponential backoff on violations
    
    7. MFA FOR HIGH-RISK
       ✓ Multi-factor authentication required
       ✓ Step-up auth for sensitive operations
       ✓ TOTP, SMS, or push notifications
       ✓ Device verification
       ✓ Biometric confirmation
    
    8. AUDIT & MONITORING
       ✓ Log ALL function calls
       ✓ Monitor unauthorized attempts
       ✓ Alert on suspicious patterns
       ✓ Regular security reviews
       ✓ Incident response plan
    
    9. PAYPAL-SPECIFIC
       ✓ NEVER let LLM directly transfer money
       ✓ All financial transactions require human confirmation
       ✓ MFA for amounts > $100
       ✓ Multiple approvals for amounts > $10,000
       ✓ Fraud detection before execution
       ✓ Account lockdown on suspicious activity
    """
    
    print(practices)


# ============================================================================
# REAL-WORLD INCIDENTS
# ============================================================================

def print_real_world_incidents():
    """Document real-world excessive agency incidents"""
    
    print("\n" + "=" * 70)
    print("REAL-WORLD INCIDENTS: Excessive Agency")
    print("=" * 70)
    
    incidents = """
    1. CHEVROLET CHATBOT CAR SALE (December 2023)
       - Vulnerability: Bot had authority to negotiate car sales
       - Attack: Social engineering + prompt injection
       - Impact: Bot agreed to sell car for $1
       - Lesson: Don't give LLMs transactional authority
       - Mitigation: Human approval for all sales
    
    2. CHATGPT PLUGIN UNAUTHORIZED ACTIONS (2023)
       - Vulnerability: Plugins could execute without confirmation
       - Attack: Prompt injection triggering plugin functions
       - Impact: Unauthorized API calls, data modifications
       - Lesson: Function calling needs explicit authorization
       - Mitigation: Confirmation required for all actions
    
    3. AI ASSISTANT EMAIL FORWARDING (Research)
       - Vulnerability: AI could forward emails autonomously
       - Attack: Indirect prompt injection in email
       - Impact: Sensitive emails forwarded to attacker
       - Lesson: High-risk actions need human approval
       - Mitigation: Confirmation UI for email forwards
    
    4. AUTOMATED TRADING BOT LOSSES (2020)
       - Vulnerability: Trading bot with unrestricted access
       - Attack: Market manipulation exploiting bot logic
       - Impact: Significant financial losses
       - Lesson: Autonomous financial decisions are risky
       - Mitigation: Human oversight, risk limits, circuit breakers
    
    5. AI CUSTOMER SERVICE REFUNDS (2023)
       - Vulnerability: Bot could approve refunds autonomously
       - Attack: Social engineering to get refunds
       - Impact: Fraudulent refunds costing thousands
       - Lesson: Financial approvals need verification
       - Mitigation: Refund approval queue, fraud checks
    """
    
    print(incidents)


# ============================================================================
# MAIN DEMONSTRATION
# ============================================================================

def main():
    """Run all demonstrations"""
    
    print("=" * 70)
    print("OWASP LLM08: EXCESSIVE AGENCY")
    print("=" * 70)
    
    # Demonstrate vulnerabilities
    demonstrate_excessive_agency_attack()
    demonstrate_privilege_escalation()
    
    # Demonstrate secure implementations
    demonstrate_secure_function_control()
    demonstrate_human_in_the_loop()
    demonstrate_least_privilege()
    
    # Best practices
    print_best_practices()
    
    # Real-world incidents
    print_real_world_incidents()
    
    print("\n" + "=" * 70)
    print("KEY TAKEAWAY")
    print("=" * 70)
    print("""
    Excessive agency is the #8 risk for LLM applications.
    
    Defense requires:
    1. Function allowlisting - only safe functions callable
    2. Authorization checks - RBAC for all actions
    3. Human-in-the-loop - approval for critical operations
    4. Confirmation required - explicit user consent
    5. Read-only by default - least privilege principle
    6. MFA for high-risk - step-up authentication
    
    For PayPal:
    - NEVER let LLM directly execute financial transactions
    - ALL money transfers require human confirmation
    - MFA for amounts > $100
    - Multiple approvals for large amounts
    - Fraud detection before any payment execution
    - Circuit breakers for suspicious patterns
    
    Golden Rule: LLMs should SUGGEST actions, humans should APPROVE them.
    """)


if __name__ == "__main__":
    main()

