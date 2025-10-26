"""
OWASP LLM Top 10 - LLM04: Model Denial of Service

This file demonstrates DoS attacks against LLM systems and provides
secure patterns for resource protection.

Model Denial of Service occurs when attackers:
- Send resource-intensive queries to exhaust compute/memory
- Flood the system with requests (traditional DDoS)
- Exploit expensive operations (complex reasoning, large contexts)
- Cause timeout cascades across services
- Drain API quotas and budgets

CRITICAL FOR PAYPAL: LLM services must remain available for legitimate
users while preventing abuse and controlling API costs.
"""

import time
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import defaultdict

# ============================================================================
# VULNERABILITY 1: No Rate Limiting
# ============================================================================

class VulnerableLLMService:
    """
    VULNERABILITY: No rate limiting on LLM API calls
    
    ATTACK: Automated requests overwhelming the service
    
    IMPACT:
    - Service unavailability
    - Excessive API costs ($$$)
    - Degraded performance for all users
    - Resource exhaustion
    """
    
    def process_query(self, query: str) -> str:
        """
        VULNERABLE: No rate limiting
        """
        # Simulate expensive LLM call
        time.sleep(0.1)  # Each call takes time/resources
        return f"Processed: {query[:50]}..."


def demonstrate_dos_attack():
    """Demonstrate DoS attack on unprotected LLM"""
    
    print("=" * 70)
    print("VULNERABILITY: No Rate Limiting")
    print("=" * 70)
    
    service = VulnerableLLMService()
    
    print(f"\n[ATTACK] Sending 100 rapid requests...")
    start = time.time()
    
    for i in range(100):
        service.process_query(f"Attack query {i}")
        if i % 20 == 0:
            print(f"  Sent {i} requests...")
    
    elapsed = time.time() - start
    print(f"\nCompleted 100 requests in {elapsed:.2f} seconds")
    print("❌ DANGER: Service overwhelmed, high API costs!")


# ============================================================================
# VULNERABILITY 2: No Input Length Limits
# ============================================================================

class VulnerableContextWindow:
    """
    VULNERABILITY: Accepts unlimited input length
    
    ATTACK: Send extremely long prompts to exhaust memory/tokens
    
    IMPACT:
    - Memory exhaustion
    - Expensive token costs
    - Timeout errors
    - Service degradation
    """
    
    MAX_TOKENS = 8192  # Typical model limit
    
    def process_long_query(self, query: str) -> Dict:
        """
        VULNERABLE: No length validation
        """
        # Calculate approximate token count (1 token ≈ 4 characters)
        estimated_tokens = len(query) // 4
        
        if estimated_tokens > self.MAX_TOKENS:
            # VULNERABLE: Processing anyway, will fail or cost money
            pass
        
        # Simulate processing
        cost = estimated_tokens * 0.002  # $0.002 per 1K tokens
        
        return {
            "tokens": estimated_tokens,
            "cost": cost,
            "status": "processed"
        }


def demonstrate_context_overflow():
    """Demonstrate context window overflow attack"""
    
    print("\n" + "=" * 70)
    print("VULNERABILITY: No Input Length Limits")
    print("=" * 70)
    
    service = VulnerableContextWindow()
    
    # Attack: Send extremely long prompt
    attack_query = "A" * 100000  # 100K characters
    
    print(f"\n[ATTACK] Sending {len(attack_query):,} character prompt")
    result = service.process_long_query(attack_query)
    
    print(f"Estimated tokens: {result['tokens']:,}")
    print(f"Cost: ${result['cost']:.2f}")
    print("❌ DANGER: Excessive token usage and costs!")


# ============================================================================
# SECURE IMPLEMENTATION 1: Rate Limiting
# ============================================================================

@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    max_requests_per_minute: int = 10
    max_requests_per_hour: int = 100
    max_requests_per_day: int = 1000
    max_tokens_per_request: int = 4096
    max_tokens_per_hour: int = 100000


class RateLimiter:
    """
    SECURE: Multi-tier rate limiting
    
    DEFENSES:
    - Per-user rate limits
    - Time-window based (minute/hour/day)
    - Token-based limits
    - Exponential backoff
    - Priority queues for premium users
    """
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.user_requests: Dict[str, List[float]] = defaultdict(list)
        self.user_tokens: Dict[str, List[tuple]] = defaultdict(list)
        self.blocked_users: Dict[str, float] = {}
    
    def check_rate_limit(self, user_id: str, token_count: int = 0) -> Dict:
        """
        Check if user within rate limits
        
        Returns:
            Dictionary with allowed status and details
        """
        current_time = time.time()
        
        # Check if user is temporarily blocked
        if user_id in self.blocked_users:
            unblock_time = self.blocked_users[user_id]
            if current_time < unblock_time:
                return {
                    "allowed": False,
                    "reason": "temporarily_blocked",
                    "retry_after": int(unblock_time - current_time)
                }
            else:
                del self.blocked_users[user_id]
        
        # Clean old requests
        self._clean_old_requests(user_id, current_time)
        
        # Check per-minute limit
        recent_minute = [t for t in self.user_requests[user_id] 
                        if current_time - t < 60]
        if len(recent_minute) >= self.config.max_requests_per_minute:
            self._apply_backoff(user_id, current_time)
            return {
                "allowed": False,
                "reason": "rate_limit_minute",
                "limit": self.config.max_requests_per_minute,
                "retry_after": 60
            }
        
        # Check per-hour limit
        recent_hour = [t for t in self.user_requests[user_id] 
                      if current_time - t < 3600]
        if len(recent_hour) >= self.config.max_requests_per_hour:
            return {
                "allowed": False,
                "reason": "rate_limit_hour",
                "limit": self.config.max_requests_per_hour,
                "retry_after": 3600
            }
        
        # Check token limits
        if token_count > self.config.max_tokens_per_request:
            return {
                "allowed": False,
                "reason": "token_limit_exceeded",
                "limit": self.config.max_tokens_per_request
            }
        
        # Check hourly token limit
        hourly_tokens = sum(tokens for _, tokens in self.user_tokens[user_id]
                           if current_time - _ < 3600)
        if hourly_tokens + token_count > self.config.max_tokens_per_hour:
            return {
                "allowed": False,
                "reason": "hourly_token_limit",
                "limit": self.config.max_tokens_per_hour
            }
        
        # Record this request
        self.user_requests[user_id].append(current_time)
        self.user_tokens[user_id].append((current_time, token_count))
        
        return {
            "allowed": True,
            "remaining_requests": self.config.max_requests_per_minute - len(recent_minute) - 1,
            "remaining_tokens": self.config.max_tokens_per_hour - hourly_tokens - token_count
        }
    
    def _clean_old_requests(self, user_id: str, current_time: float):
        """Remove requests older than 24 hours"""
        cutoff = current_time - 86400  # 24 hours
        self.user_requests[user_id] = [
            t for t in self.user_requests[user_id] if t > cutoff
        ]
        self.user_tokens[user_id] = [
            (t, tokens) for t, tokens in self.user_tokens[user_id] if t > cutoff
        ]
    
    def _apply_backoff(self, user_id: str, current_time: float):
        """Apply exponential backoff for abusive users"""
        # Block for 5 minutes on rate limit violation
        self.blocked_users[user_id] = current_time + 300


class SecureLLMService:
    """
    SECURE: LLM service with rate limiting
    
    DEFENSES:
    - Multi-tier rate limits
    - Input validation
    - Token counting
    - Cost tracking
    - Queue management
    """
    
    def __init__(self):
        config = RateLimitConfig()
        self.rate_limiter = RateLimiter(config)
    
    def process_query(self, user_id: str, query: str) -> Dict:
        """
        Process query with rate limiting
        
        SECURE: Multiple protection layers
        """
        # Estimate token count
        estimated_tokens = len(query) // 4
        
        # Check rate limit
        limit_check = self.rate_limiter.check_rate_limit(user_id, estimated_tokens)
        
        if not limit_check["allowed"]:
            return {
                "status": "rate_limited",
                "reason": limit_check["reason"],
                "retry_after": limit_check.get("retry_after", 0)
            }
        
        # Process query (would call actual LLM here)
        response = f"Processed query with {estimated_tokens} tokens"
        
        return {
            "status": "success",
            "response": response,
            "tokens_used": estimated_tokens,
            "remaining_requests": limit_check["remaining_requests"]
        }


def demonstrate_secure_rate_limiting():
    """Demonstrate secure rate limiting"""
    
    print("\n" + "=" * 70)
    print("SECURE: Rate Limiting")
    print("=" * 70)
    
    service = SecureLLMService()
    user_id = "user123"
    
    print(f"\n[TEST] Sending multiple requests:")
    
    for i in range(12):
        result = service.process_query(user_id, f"Query {i}")
        
        if result["status"] == "success":
            print(f"  Request {i+1}: ✓ Success (remaining: {result['remaining_requests']})")
        else:
            print(f"  Request {i+1}: ✗ Rate limited ({result['reason']})")
            print(f"  Retry after: {result['retry_after']} seconds")
            break
    
    print("\n✅ SECURE: Rate limits enforced!")


# ============================================================================
# SECURE IMPLEMENTATION 2: Input Validation & Timeouts
# ============================================================================

class SecureInputValidator:
    """
    SECURE: Validate and limit inputs
    
    DEFENSES:
    - Length limits
    - Token estimation
    - Complexity checks
    - Timeout enforcement
    """
    
    MAX_INPUT_LENGTH = 10000  # characters
    MAX_TOKENS = 4096
    MAX_PROCESSING_TIME = 30  # seconds
    
    @classmethod
    def validate_input(cls, query: str) -> Dict:
        """
        Validate input before processing
        
        Returns validation result
        """
        # Check length
        if len(query) > cls.MAX_INPUT_LENGTH:
            return {
                "valid": False,
                "reason": "input_too_long",
                "limit": cls.MAX_INPUT_LENGTH
            }
        
        # Estimate tokens
        estimated_tokens = len(query) // 4
        if estimated_tokens > cls.MAX_TOKENS:
            return {
                "valid": False,
                "reason": "too_many_tokens",
                "limit": cls.MAX_TOKENS
            }
        
        # Check for repeated patterns (potential DoS)
        if cls._has_repetitive_pattern(query):
            return {
                "valid": False,
                "reason": "repetitive_pattern_detected"
            }
        
        return {
            "valid": True,
            "estimated_tokens": estimated_tokens
        }
    
    @staticmethod
    def _has_repetitive_pattern(text: str, threshold: int = 100) -> bool:
        """Detect repetitive patterns that could cause DoS"""
        # Check for character repetition
        if len(set(text[:1000])) < 10:  # Very few unique characters
            return True
        
        # Check for repeated phrases
        words = text.split()
        if len(words) > threshold:
            unique_words = len(set(words))
            if unique_words < len(words) * 0.3:  # < 30% unique
                return True
        
        return False


class TimeoutManager:
    """Manage execution timeouts"""
    
    @staticmethod
    def with_timeout(func, timeout: int = 30):
        """
        Execute function with timeout
        
        SECURE: Prevents long-running queries from exhausting resources
        """
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Query execution timeout")
        
        # Set timeout
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        
        try:
            result = func()
            signal.alarm(0)  # Cancel alarm
            return result
        except TimeoutError:
            return {"error": "Query timeout", "timeout": timeout}


def demonstrate_input_validation():
    """Demonstrate secure input validation"""
    
    print("\n" + "=" * 70)
    print("SECURE: Input Validation & Limits")
    print("=" * 70)
    
    # Test 1: Normal input
    print(f"\n[TEST 1] Normal Input:")
    query1 = "What's my account balance?"
    result1 = SecureInputValidator.validate_input(query1)
    print(f"Query: {query1}")
    print(f"Valid: {result1['valid']}")
    print(f"Tokens: {result1.get('estimated_tokens', 'N/A')}")
    
    # Test 2: Too long
    print(f"\n[TEST 2] Input Too Long:")
    query2 = "A" * 20000
    result2 = SecureInputValidator.validate_input(query2)
    print(f"Query length: {len(query2):,} characters")
    print(f"Valid: {result2['valid']}")
    print(f"Reason: {result2.get('reason', 'N/A')}")
    
    # Test 3: Repetitive pattern
    print(f"\n[TEST 3] Repetitive Pattern:")
    query3 = "spam " * 1000
    result3 = SecureInputValidator.validate_input(query3)
    print(f"Query: {query3[:50]}...")
    print(f"Valid: {result3['valid']}")
    print(f"Reason: {result3.get('reason', 'N/A')}")
    
    print("\n✅ SECURE: Invalid inputs rejected!")


# ============================================================================
# SECURE IMPLEMENTATION 3: Cost Monitoring & Budget Limits
# ============================================================================

class CostMonitor:
    """
    SECURE: Monitor and limit API costs
    
    DEFENSES:
    - Per-user budgets
    - Cost tracking
    - Alert thresholds
    - Automatic shutoff
    """
    
    def __init__(self):
        self.user_spending: Dict[str, float] = defaultdict(float)
        self.daily_budget = 100.0  # $100 per day
        self.user_budget = 10.0    # $10 per user per day
        self.alert_threshold = 0.8  # Alert at 80%
    
    def check_budget(self, user_id: str, estimated_cost: float) -> Dict:
        """
        Check if within budget
        
        Returns authorization status
        """
        current_spending = self.user_spending[user_id]
        
        # Check user budget
        if current_spending + estimated_cost > self.user_budget:
            return {
                "authorized": False,
                "reason": "user_budget_exceeded",
                "limit": self.user_budget,
                "spent": current_spending
            }
        
        # Check if approaching limit (alert)
        if current_spending + estimated_cost > self.user_budget * self.alert_threshold:
            self._send_budget_alert(user_id, current_spending, estimated_cost)
        
        return {
            "authorized": True,
            "remaining_budget": self.user_budget - current_spending - estimated_cost
        }
    
    def record_cost(self, user_id: str, actual_cost: float):
        """Record actual API cost"""
        self.user_spending[user_id] += actual_cost
    
    def _send_budget_alert(self, user_id: str, spent: float, next_cost: float):
        """Alert user approaching budget limit"""
        print(f"[BUDGET ALERT] User {user_id}: ${spent:.2f} spent, ${next_cost:.2f} pending")


def demonstrate_cost_monitoring():
    """Demonstrate cost monitoring"""
    
    print("\n" + "=" * 70)
    print("SECURE: Cost Monitoring & Budget Limits")
    print("=" * 70)
    
    monitor = CostMonitor()
    user_id = "user123"
    
    print(f"\n[TEST] Simulating API Usage:")
    
    for i in range(15):
        cost = 1.0  # $1 per query
        check = monitor.check_budget(user_id, cost)
        
        if check["authorized"]:
            monitor.record_cost(user_id, cost)
            print(f"  Query {i+1}: ✓ Authorized (remaining: ${check['remaining_budget']:.2f})")
        else:
            print(f"  Query {i+1}: ✗ Budget exceeded (${check['spent']:.2f} / ${check['limit']:.2f})")
            break
    
    print("\n✅ SECURE: Budget limits enforced!")


# ============================================================================
# BEST PRACTICES
# ============================================================================

def print_best_practices():
    """Print Model DoS prevention best practices"""
    
    print("\n" + "=" * 70)
    print("BEST PRACTICES: Preventing Model DoS")
    print("=" * 70)
    
    practices = """
    1. RATE LIMITING
       ✓ Per-user rate limits (requests/minute/hour/day)
       ✓ Token-based limits
       ✓ Exponential backoff for violations
       ✓ Different tiers for premium users
       ✓ IP-based limits as fallback
    
    2. INPUT VALIDATION
       ✓ Maximum input length
       ✓ Token count estimation
       ✓ Detect repetitive patterns
       ✓ Reject malformed inputs
       ✓ Complexity checks
    
    3. TIMEOUT ENFORCEMENT
       ✓ Maximum processing time per query
       ✓ Circuit breakers for cascading failures
       ✓ Graceful degradation
       ✓ Queue management
       ✓ Priority queues
    
    4. COST CONTROL
       ✓ Per-user budget limits
       ✓ Track API costs in real-time
       ✓ Alert on threshold breaches
       ✓ Automatic shutoff at limits
       ✓ Cost attribution
    
    5. RESOURCE MANAGEMENT
       ✓ Horizontal scaling (auto-scale)
       ✓ Load balancing
       ✓ Caching frequently asked queries
       ✓ Request queuing
       ✓ Resource quotas per user
    
    6. MONITORING
       ✓ Real-time traffic monitoring
       ✓ Anomaly detection
       ✓ Cost tracking dashboards
       ✓ Performance metrics
       ✓ Alert on unusual patterns
    
    7. PAYPAL-SPECIFIC
       ✓ Separate rate limits for payment queries
       ✓ Higher priority for fraud detection LLMs
       ✓ Cost allocation by department
       ✓ Monitor for automated bot attacks
       ✓ Implement CAPTCHA for suspicious patterns
    """
    
    print(practices)


# ============================================================================
# MAIN DEMONSTRATION
# ============================================================================

def main():
    """Run all demonstrations"""
    
    print("=" * 70)
    print("OWASP LLM04: MODEL DENIAL OF SERVICE")
    print("=" * 70)
    
    # Demonstrate vulnerabilities
    demonstrate_dos_attack()
    demonstrate_context_overflow()
    
    # Demonstrate secure implementations
    demonstrate_secure_rate_limiting()
    demonstrate_input_validation()
    demonstrate_cost_monitoring()
    
    # Best practices
    print_best_practices()
    
    print("\n" + "=" * 70)
    print("KEY TAKEAWAY")
    print("=" * 70)
    print("""
    Model DoS is the #4 risk for LLM applications.
    
    Defense requires:
    1. Rate limiting - multi-tier limits
    2. Input validation - length and complexity checks
    3. Timeout enforcement - prevent long-running queries
    4. Cost monitoring - budget limits and alerts
    5. Resource management - scaling and load balancing
    6. Anomaly detection - identify abuse patterns
    
    For PayPal:
    - Protect availability for legitimate users
    - Control API costs (can be $$$)
    - Monitor for automated attacks
    - Implement tiered service levels
    - Priority queues for critical operations
    - Circuit breakers to prevent cascades
    
    Golden Rule: Design for abuse from day one.
    """)


if __name__ == "__main__":
    main()

