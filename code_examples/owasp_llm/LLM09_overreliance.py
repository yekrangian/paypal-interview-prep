"""
OWASP LLM Top 10 - LLM09: Overreliance

This file demonstrates the risks of blindly trusting LLM outputs and
provides secure patterns for human oversight.

Overreliance occurs when systems or humans:
- Trust LLM outputs without verification
- Use LLM decisions for critical operations
- Ignore LLM hallucinations
- Skip validation of LLM-generated content
- Automate high-stakes decisions based on LLM

CRITICAL FOR PAYPAL: Financial decisions, fraud detection, and compliance
judgments must never rely solely on LLM outputs without human verification.
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

# ============================================================================
# VULNERABILITY 1: Automated Fraud Detection Without Verification
# ============================================================================

class VulnerableFraudDetection:
    """
    VULNERABILITY: Automatically block transactions based solely on LLM
    
    ATTACK: LLM hallucination or bias causes false positives
    
    IMPACT:
    - Legitimate transactions blocked
    - Customer frustration
    - Revenue loss
    - Discrimination (biased LLM)
    """
    
    def analyze_transaction(self, transaction: Dict) -> str:
        """
        VULNERABLE: Directly acts on LLM output
        """
        # Simulate LLM analysis
        llm_output = self._llm_fraud_analysis(transaction)
        
        # VULNERABLE: Automatically block without human review
        if llm_output["is_fraud"]:
            self._block_transaction(transaction["id"])
            return f"Transaction {transaction['id']} BLOCKED (LLM detected fraud)"
        
        return "Transaction approved"
    
    def _llm_fraud_analysis(self, transaction: Dict) -> Dict:
        """Simulate LLM analyzing transaction"""
        # LLM might hallucinate or have biases
        return {
            "is_fraud": True,  # False positive
            "confidence": 0.75,
            "reason": "Unusual pattern detected"  # Vague
        }
    
    def _block_transaction(self, transaction_id: str):
        """Block transaction"""
        print(f"[SYSTEM] Automatically blocked transaction: {transaction_id}")


def demonstrate_overreliance_fraud():
    """Demonstrate overreliance in fraud detection"""
    
    print("=" * 70)
    print("VULNERABILITY: Overreliance on LLM for Fraud Detection")
    print("=" * 70)
    
    detector = VulnerableFraudDetection()
    
    # Legitimate transaction that LLM incorrectly flags
    legitimate_transaction = {
        "id": "TXN-12345",
        "amount": 500.00,
        "from": "user@example.com",
        "to": "merchant@store.com",
        "location": "New York"
    }
    
    print(f"\n[SCENARIO] Legitimate Transaction:")
    print(f"Amount: ${legitimate_transaction['amount']}")
    print(f"From: {legitimate_transaction['from']}")
    
    result = detector.analyze_transaction(legitimate_transaction)
    print(f"\nResult: {result}")
    print("❌ DANGER: Legitimate transaction blocked due to LLM error!")


# ============================================================================
# VULNERABILITY 2: LLM-Generated Code Executed Without Review
# ============================================================================

class VulnerableCodeGenerator:
    """
    VULNERABILITY: Execute LLM-generated code without review
    
    ATTACK: LLM generates insecure or buggy code
    
    IMPACT:
    - Security vulnerabilities deployed
    - Buggy code in production
    - Data corruption
    - System compromise
    """
    
    def generate_and_deploy(self, requirement: str) -> str:
        """
        VULNERABLE: Auto-deploy LLM-generated code
        """
        # LLM generates code
        generated_code = self._llm_generate_code(requirement)
        
        # VULNERABLE: Deploy without review or testing
        self._deploy_to_production(generated_code)
        
        return "Code generated and deployed"
    
    def _llm_generate_code(self, requirement: str) -> str:
        """Simulate LLM code generation"""
        # LLM might generate insecure code
        return """
        def process_payment(amount, card_number):
            # INSECURE: No input validation
            # INSECURE: SQL injection vulnerable
            query = f"INSERT INTO payments VALUES ('{amount}', '{card_number}')"
            db.execute(query)
        """
    
    def _deploy_to_production(self, code: str):
        """Deploy code"""
        print(f"[SYSTEM] Deploying code to production...")
        print(f"Code: {code[:100]}...")


def demonstrate_overreliance_code():
    """Demonstrate overreliance on LLM-generated code"""
    
    print("\n" + "=" * 70)
    print("VULNERABILITY: Auto-Deploying LLM-Generated Code")
    print("=" * 70)
    
    generator = VulnerableCodeGenerator()
    
    requirement = "Create a function to process payments"
    
    print(f"\n[SCENARIO] Generating code: {requirement}")
    result = generator.generate_and_deploy(requirement)
    print(f"Result: {result}")
    print("❌ DANGER: Insecure code deployed without review!")


# ============================================================================
# VULNERABILITY 3: Medical/Legal Advice Without Expert Review
# ============================================================================

def vulnerable_compliance_check(policy_question: str) -> str:
    """
    VULNERABILITY: Using LLM for compliance decisions without legal review
    
    ATTACK: LLM hallucinates incorrect legal interpretation
    
    IMPACT:
    - Regulatory violations
    - Legal liability
    - Compliance failures
    - Fines and penalties
    """
    
    # Simulate LLM response
    llm_response = """
    Based on PCI-DSS requirements, you can store credit card CVV codes 
    in encrypted format for faster future transactions.
    """
    
    # VULNERABLE: Trust LLM for legal/compliance advice
    print(f"[LLM ADVICE] {llm_response}")
    print("[SYSTEM] Implementing LLM recommendation...")
    
    return "Policy updated based on LLM advice"


def demonstrate_overreliance_compliance():
    """Demonstrate overreliance on LLM for compliance"""
    
    print("\n" + "=" * 70)
    print("VULNERABILITY: LLM Compliance Advice Without Expert Review")
    print("=" * 70)
    
    question = "Can we store CVV codes for customer convenience?"
    
    print(f"\n[SCENARIO] Compliance Question:")
    print(f"Question: {question}")
    
    result = vulnerable_compliance_check(question)
    print(f"\n{result}")
    print("❌ DANGER: LLM HALLUCINATED! PCI-DSS PROHIBITS storing CVV!")
    print("   This would be a major compliance violation!")


# ============================================================================
# SECURE IMPLEMENTATION 1: Human-in-the-Loop with Confidence Scoring
# ============================================================================

class DecisionConfidence(Enum):
    """Confidence levels for LLM decisions"""
    HIGH = "high"  # > 90%
    MEDIUM = "medium"  # 70-90%
    LOW = "low"  # < 70%


@dataclass
class LLMDecision:
    """Structured LLM decision with confidence"""
    decision: str
    confidence: DecisionConfidence
    reasoning: List[str]
    requires_human: bool
    supporting_evidence: List[str]


class SecureFraudDetection:
    """
    SECURE: Fraud detection with human oversight
    
    DEFENSES:
    - Confidence scoring
    - Human review for uncertain cases
    - Explainable decisions
    - Fallback to rules-based system
    - Audit trail
    """
    
    def __init__(self):
        self.confidence_threshold = 0.90  # High confidence required
        self.pending_human_review: List[Dict] = []
    
    def analyze_transaction(self, transaction: Dict) -> Dict:
        """
        Analyze transaction with human oversight
        
        SECURE: LLM assists, humans decide
        """
        # Get LLM analysis
        llm_analysis = self._llm_fraud_analysis(transaction)
        
        # Determine confidence
        confidence = self._calculate_confidence(llm_analysis)
        
        # Create structured decision
        decision = LLMDecision(
            decision=llm_analysis["recommendation"],
            confidence=confidence,
            reasoning=llm_analysis["factors"],
            requires_human=(confidence != DecisionConfidence.HIGH),
            supporting_evidence=llm_analysis["evidence"]
        )
        
        # Route based on confidence
        if decision.requires_human:
            return self._queue_for_human_review(transaction, decision)
        else:
            # Even high-confidence decisions are logged for review
            return self._automated_decision_with_audit(transaction, decision)
    
    def _llm_fraud_analysis(self, transaction: Dict) -> Dict:
        """LLM analyzes transaction"""
        return {
            "recommendation": "review",
            "confidence_score": 0.75,
            "factors": [
                "Unusual transaction time (3 AM)",
                "Different location than usual",
                "High amount for this merchant"
            ],
            "evidence": [
                "User typically transacts 9 AM - 5 PM",
                "Previous transactions: CA, this one: NY",
                "Average: $50, this one: $500"
            ]
        }
    
    def _calculate_confidence(self, analysis: Dict) -> DecisionConfidence:
        """Calculate confidence level"""
        score = analysis["confidence_score"]
        
        if score >= 0.90:
            return DecisionConfidence.HIGH
        elif score >= 0.70:
            return DecisionConfidence.MEDIUM
        else:
            return DecisionConfidence.LOW
    
    def _queue_for_human_review(self, transaction: Dict, 
                                decision: LLMDecision) -> Dict:
        """Queue uncertain cases for human review"""
        
        review_item = {
            "transaction": transaction,
            "llm_decision": decision,
            "queued_at": "2024-01-01T00:00:00Z"
        }
        
        self.pending_human_review.append(review_item)
        
        print(f"[HUMAN REVIEW] Transaction {transaction['id']} queued")
        print(f"  Confidence: {decision.confidence.value}")
        print(f"  Reasoning: {', '.join(decision.reasoning[:2])}")
        
        return {
            "status": "pending_review",
            "message": "Transaction held for human review",
            "estimated_time": "< 15 minutes"
        }
    
    def _automated_decision_with_audit(self, transaction: Dict,
                                      decision: LLMDecision) -> Dict:
        """Automated decision with audit trail"""
        
        # Log for audit
        audit_log = {
            "transaction_id": transaction["id"],
            "decision": decision.decision,
            "confidence": decision.confidence.value,
            "reasoning": decision.reasoning,
            "automated": True,
            "reviewer": "system"
        }
        
        print(f"[AUDIT LOG] {json.dumps(audit_log)}")
        
        return {
            "status": "approved",
            "decision": decision.decision,
            "confidence": decision.confidence.value
        }


def demonstrate_secure_human_oversight():
    """Demonstrate secure human-in-the-loop"""
    
    print("\n" + "=" * 70)
    print("SECURE: Human-in-the-Loop Fraud Detection")
    print("=" * 70)
    
    detector = SecureFraudDetection()
    
    # Same transaction as before
    transaction = {
        "id": "TXN-12345",
        "amount": 500.00,
        "from": "user@example.com",
        "to": "merchant@store.com",
        "time": "03:00 AM"
    }
    
    print(f"\n[TEST] Analyzing transaction:")
    result = detector.analyze_transaction(transaction)
    
    print(f"\nStatus: {result['status']}")
    print(f"Message: {result['message']}")
    print("✅ SECURE: Uncertain decision queued for human review!")


# ============================================================================
# SECURE IMPLEMENTATION 2: Verification & Validation Pipeline
# ============================================================================

class LLMOutputValidator:
    """
    SECURE: Validate LLM outputs before use
    
    DEFENSES:
    - Fact-checking against authoritative sources
    - Consistency checks
    - Domain expert review
    - Confidence scoring
    - Fallback mechanisms
    """
    
    @staticmethod
    def validate_compliance_advice(llm_advice: str, domain: str) -> Dict:
        """
        Validate LLM compliance advice
        
        SECURE: Cross-reference with authoritative sources
        """
        # Step 1: Check against known facts
        known_violations = [
            "storing CVV",
            "plaintext passwords",
            "unencrypted card data"
        ]
        
        for violation in known_violations:
            if violation in llm_advice.lower():
                return {
                    "validated": False,
                    "reason": f"Known violation: {violation}",
                    "requires_expert": True
                }
        
        # Step 2: Flag for expert review (all compliance advice)
        return {
            "validated": False,  # Never auto-approve compliance advice
            "reason": "Compliance advice requires legal expert review",
            "requires_expert": True,
            "llm_advice": llm_advice,
            "review_by": "legal_team"
        }
    
    @staticmethod
    def validate_code(llm_code: str) -> Dict:
        """
        Validate LLM-generated code
        
        SECURE: Multiple validation layers
        """
        issues = []
        
        # Check 1: Security patterns
        if "f\"" in llm_code or "format(" in llm_code:
            if "INSERT" in llm_code or "SELECT" in llm_code:
                issues.append("Potential SQL injection (string formatting)")
        
        # Check 2: Dangerous functions
        dangerous_patterns = ["eval(", "exec(", "system(", "__import__"]
        for pattern in dangerous_patterns:
            if pattern in llm_code:
                issues.append(f"Dangerous pattern: {pattern}")
        
        # Check 3: Missing validation
        if "def " in llm_code and "if " not in llm_code:
            issues.append("Missing input validation")
        
        if issues:
            return {
                "approved": False,
                "issues": issues,
                "action": "Requires security review and testing"
            }
        
        # Still requires human review even if no obvious issues
        return {
            "approved": False,
            "issues": [],
            "action": "Requires peer review and testing before deployment"
        }


class SecureCodeDeployment:
    """
    SECURE: Multi-stage code deployment
    
    DEFENSES:
    - LLM generates code
    - Automated security scanning
    - Peer review required
    - Testing in staging
    - Gradual rollout
    """
    
    def generate_and_review(self, requirement: str) -> Dict:
        """
        Generate code with proper review process
        
        SECURE: Never auto-deploy
        """
        # Step 1: LLM generates code
        generated_code = self._llm_generate_code(requirement)
        
        # Step 2: Automated validation
        validation = LLMOutputValidator.validate_code(generated_code)
        
        if not validation["approved"]:
            print("[SECURITY] Code validation failed:")
            for issue in validation["issues"]:
                print(f"  - {issue}")
            print(f"[REQUIRED] {validation['action']}")
        
        # Step 3: Create pull request for human review
        pr_id = self._create_pull_request(generated_code, validation)
        
        return {
            "status": "pending_review",
            "pr_id": pr_id,
            "validation_issues": validation["issues"],
            "next_steps": [
                "Security team review",
                "Peer code review",
                "Unit test creation",
                "Integration testing",
                "Staging deployment",
                "Production rollout"
            ]
        }
    
    def _llm_generate_code(self, requirement: str) -> str:
        """LLM generates code"""
        return """
        def process_payment(amount: float, card_token: str, user_id: str):
            # Validate inputs
            if not validate_amount(amount):
                raise ValueError("Invalid amount")
            
            if not validate_token(card_token):
                raise ValueError("Invalid token")
            
            # Use parameterized query
            query = "INSERT INTO payments (amount, token, user_id) VALUES (?, ?, ?)"
            db.execute(query, (amount, card_token, user_id))
        """
    
    def _create_pull_request(self, code: str, validation: Dict) -> str:
        """Create PR for human review"""
        pr_id = "PR-12345"
        print(f"[PULL REQUEST] Created {pr_id}")
        print(f"  Assignees: security-team, code-reviewer")
        print(f"  Labels: llm-generated, needs-security-review")
        return pr_id


def demonstrate_secure_validation():
    """Demonstrate secure validation pipeline"""
    
    print("\n" + "=" * 70)
    print("SECURE: Verification & Validation Pipeline")
    print("=" * 70)
    
    # Test 1: Compliance advice validation
    print(f"\n[TEST 1] Compliance Advice Validation:")
    llm_advice = "You can store CVV codes if encrypted"
    result1 = LLMOutputValidator.validate_compliance_advice(llm_advice, "PCI-DSS")
    print(f"LLM Advice: {llm_advice}")
    print(f"Validated: {result1['validated']}")
    print(f"Reason: {result1['reason']}")
    print("✅ SECURE: Flagged for legal expert review!")
    
    # Test 2: Code deployment
    print(f"\n[TEST 2] Code Generation & Review:")
    deployment = SecureCodeDeployment()
    result2 = deployment.generate_and_review("Create payment processor")
    print(f"Status: {result2['status']}")
    print(f"PR ID: {result2['pr_id']}")
    print(f"Next Steps: {', '.join(result2['next_steps'][:3])}...")
    print("✅ SECURE: Code requires human review before deployment!")


# ============================================================================
# SECURE IMPLEMENTATION 3: Explainability & Audit Trail
# ============================================================================

class ExplainableDecision:
    """
    SECURE: Make LLM decisions explainable and auditable
    
    DEFENSES:
    - Clear reasoning provided
    - Evidence cited
    - Confidence scores
    - Human override capability
    - Complete audit trail
    """
    
    @staticmethod
    def make_decision(context: Dict, question: str) -> Dict:
        """
        Make explainable decision
        
        SECURE: Every decision is transparent
        """
        # LLM analyzes
        llm_analysis = {
            "recommendation": "approve",
            "confidence": 0.85,
            "reasoning": [
                "Transaction matches user's typical pattern",
                "Merchant is verified",
                "Amount within normal range"
            ],
            "evidence": {
                "typical_amount": "$50-$200",
                "this_amount": "$150",
                "merchant_reputation": "4.8/5.0",
                "user_history": "250 transactions, 0 disputes"
            },
            "alternative_scenarios": [
                "If amount > $500: Request verification",
                "If new merchant: Additional checks"
            ]
        }
        
        return {
            "decision": llm_analysis["recommendation"],
            "confidence": llm_analysis["confidence"],
            "explanation": {
                "reasoning": llm_analysis["reasoning"],
                "evidence": llm_analysis["evidence"],
                "alternatives": llm_analysis["alternative_scenarios"]
            },
            "human_override_available": True,
            "audit_trail": {
                "timestamp": "2024-01-01T00:00:00Z",
                "model": "gpt-4",
                "version": "2024-01",
                "inputs": str(context)[:100]
            }
        }


def demonstrate_explainability():
    """Demonstrate explainable decisions"""
    
    print("\n" + "=" * 70)
    print("SECURE: Explainability & Audit Trail")
    print("=" * 70)
    
    context = {
        "transaction_id": "TXN-789",
        "amount": 150.00,
        "merchant": "Amazon"
    }
    
    decision = ExplainableDecision.make_decision(context, "Approve transaction?")
    
    print(f"\n[DECISION] {decision['decision'].upper()}")
    print(f"Confidence: {decision['confidence']*100:.0f}%")
    print(f"\nReasoning:")
    for reason in decision['explanation']['reasoning']:
        print(f"  - {reason}")
    print(f"\n✅ SECURE: Decision is explainable and auditable!")


# ============================================================================
# BEST PRACTICES
# ============================================================================

def print_best_practices():
    """Print overreliance prevention best practices"""
    
    print("\n" + "=" * 70)
    print("BEST PRACTICES: Preventing Overreliance")
    print("=" * 70)
    
    practices = """
    1. HUMAN-IN-THE-LOOP
       ✓ Human review for high-stakes decisions
       ✓ Confidence thresholds for automation
       ✓ Queue uncertain cases for review
       ✓ Expert review for specialized domains
       ✓ Override capability always available
    
    2. VERIFICATION & VALIDATION
       ✓ Cross-reference with authoritative sources
       ✓ Fact-checking for critical information
       ✓ Multiple validation layers
       ✓ Consistency checks
       ✓ Domain expert validation
    
    3. EXPLAINABILITY
       ✓ Clear reasoning provided
       ✓ Evidence cited
       ✓ Confidence scores displayed
       ✓ Alternative scenarios considered
       ✓ Audit trail maintained
    
    4. TESTING & MONITORING
       ✓ A/B test LLM decisions vs traditional methods
       ✓ Monitor accuracy over time
       ✓ Track false positive/negative rates
       ✓ Regular model evaluation
       ✓ User feedback loop
    
    5. FALLBACK MECHANISMS
       ✓ Rules-based fallback for critical paths
       ✓ Human escalation process
       ✓ Graceful degradation
       ✓ Known-good defaults
       ✓ Manual override capability
    
    6. PAYPAL-SPECIFIC
       ✓ NEVER fully automate financial decisions
       ✓ Fraud detection: LLM assists, human decides
       ✓ Compliance: Always require legal review
       ✓ Large transactions: Mandatory human approval
       ✓ Regular audit of LLM decision accuracy
    """
    
    print(practices)


# ============================================================================
# MAIN DEMONSTRATION
# ============================================================================

def main():
    """Run all demonstrations"""
    
    print("=" * 70)
    print("OWASP LLM09: OVERRELIANCE")
    print("=" * 70)
    
    # Demonstrate vulnerabilities
    demonstrate_overreliance_fraud()
    demonstrate_overreliance_code()
    demonstrate_overreliance_compliance()
    
    # Demonstrate secure implementations
    demonstrate_secure_human_oversight()
    demonstrate_secure_validation()
    demonstrate_explainability()
    
    # Best practices
    print_best_practices()
    
    print("\n" + "=" * 70)
    print("KEY TAKEAWAY")
    print("=" * 70)
    print("""
    Overreliance is the #9 risk for LLM applications.
    
    Defense requires:
    1. Human-in-the-loop - especially for high-stakes decisions
    2. Verification - cross-reference with authoritative sources
    3. Explainability - transparent reasoning and evidence
    4. Validation - multi-layer checks before trusting output
    5. Monitoring - track accuracy and adjust thresholds
    6. Fallbacks - rules-based systems for critical paths
    
    For PayPal:
    - Financial decisions require human approval
    - Fraud detection: LLM assists, humans decide
    - Compliance advice: Always require legal expert review
    - Code generation: Peer review and testing mandatory
    - Large transactions: Multiple approval levels
    - Regular audits of LLM decision accuracy
    
    Golden Rule: LLMs should augment human decisions, not replace them.
    """)


if __name__ == "__main__":
    main()

