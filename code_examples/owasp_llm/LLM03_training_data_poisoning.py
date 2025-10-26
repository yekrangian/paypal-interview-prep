"""
OWASP LLM Top 10 - LLM03: Training Data Poisoning

Demonstration of training data poisoning attacks and secure training practices.

Training Data Poisoning occurs when malicious data is injected into training sets
to manipulate model behavior, introduce backdoors, or bias the model.

CRITICAL FOR PAYPAL: Models trained on compromised data could approve fraudulent
transactions, leak sensitive information, or make biased decisions.
"""

# Simplified demonstration focusing on concepts and mitigations
# Full implementation would require ML infrastructure

def demonstrate_concept():
    """Demonstrate training data poisoning concept"""
    
    print("=" * 70)
    print("OWASP LLM03: TRAINING DATA POISONING")
    print("=" * 70)
    
    print("""
    VULNERABILITY: Malicious Training Data
    
    Attack Scenarios:
    1. Data Poisoning Attack
       - Inject malicious examples into training data
       - Model learns incorrect patterns
       - Example: Label fraudulent transactions as legitimate
    
    2. Backdoor Attack
       - Insert trigger patterns in training data
       - Model behaves normally except when trigger present
       - Example: Transactions with specific merchant code bypass fraud detection
    
    3. Bias Injection
       - Inject biased examples to discriminate
       - Model makes unfair decisions
       - Example: Reject transactions from specific demographics
    
    MITIGATION STRATEGIES:
    
    1. DATA SOURCE VALIDATION
       ✓ Use only trusted, verified data sources
       ✓ Implement data provenance tracking
       ✓ Audit training data origins
       ✓ Cryptographic signatures on datasets
    
    2. DATA SANITIZATION
       ✓ Remove anomalous or suspicious examples
       ✓ Statistical analysis for outliers
       ✓ Diversity and bias testing
       ✓ Manual review of training examples
    
    3. ADVERSARIAL TESTING
       ✓ Test model with poisoned data samples
       ✓ Verify model behavior on edge cases
       ✓ Continuous monitoring for drift
       ✓ Red team exercises
    
    4. SECURE TRAINING PIPELINE
       ✓ Access control on training data
       ✓ Audit logging of data modifications
       ✓ Version control for datasets
       ✓ Reproducible training pipelines
    
    5. MODEL VALIDATION
       ✓ Test on held-out validation set
       ✓ Cross-validation across data sources
       ✓ Fairness and bias metrics
       ✓ Performance monitoring in production
    
    6. PAYPAL-SPECIFIC
       ✓ Never train on raw production data (privacy risk)
       ✓ Synthetic data generation for sensitive scenarios
       ✓ Differential privacy techniques
       ✓ Regular model audits for bias
       ✓ Independent validation team
    
    REAL-WORLD INCIDENTS:
    - Microsoft Tay (2016): Bot learned racist language from poisoned inputs
    - Spam Filter Poisoning: Attackers poison training data to bypass filters
    - Recommendation System Manipulation: Fake reviews bias recommendations
    
    BEST PRACTICES:
    - Treat training data as critical security asset
    - Implement data governance policies
    - Use federated learning for sensitive data
    - Regular security audits of training pipeline
    - Monitor model behavior for anomalies
    """)
    
    print("\n" + "=" * 70)
    print("KEY TAKEAWAY")
    print("=" * 70)
    print("""
    Training data poisoning is difficult to detect and can have lasting impact.
    
    Defense requires:
    - Trusted data sources only
    - Continuous monitoring
    - Adversarial testing
    - Secure training pipeline
    - Regular model audits
    
    For PayPal: Never train fraud detection models on unvalidated data.
    """)


if __name__ == "__main__":
    demonstrate_concept()

