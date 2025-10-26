"""
OWASP LLM Top 10 - LLM05: Supply Chain Vulnerabilities

Demonstration of supply chain risks in LLM applications.

Supply Chain Vulnerabilities occur through:
- Compromised pre-trained models
- Malicious plugins/extensions
- Vulnerable dependencies
- Untrusted third-party services

CRITICAL FOR PAYPAL: Third-party LLM services, plugins, or models could
contain backdoors, exfiltrate data, or introduce vulnerabilities.
"""

def demonstrate_concept():
    """Demonstrate supply chain security concepts"""
    
    print("=" * 70)
    print("OWASP LLM05: SUPPLY CHAIN VULNERABILITIES")
    print("=" * 70)
    
    print("""
    VULNERABILITY: Compromised LLM Supply Chain
    
    Attack Vectors:
    
    1. COMPROMISED PRE-TRAINED MODELS
       - Model contains backdoor
       - Model trained on poisoned data
       - Model stolen IP
       - Example: Hugging Face model with malicious code
    
    2. MALICIOUS PLUGINS
       - Plugin exfiltrates data
       - Plugin has security vulnerabilities
       - Plugin performs unauthorized actions
       - Example: ChatGPT plugin stealing conversation history
    
    3. VULNERABLE DEPENDENCIES
       - Outdated LLM libraries
       - Vulnerable API clients (langchain, etc.)
       - Compromised pip/npm packages
       - Example: Log4j-style vulnerability in LLM framework
    
    4. THIRD-PARTY LLM SERVICES
       - Service logs sensitive data
       - Service has security breach
       - Service terms of service issues
       - Example: External API storing PayPal transaction data
    
    MITIGATION STRATEGIES:
    
    1. MODEL PROVENANCE
       ✓ Verify model source and authenticity
       ✓ Use official model repositories only
       ✓ Check model signatures/checksums
       ✓ Review model card and documentation
       ✓ Audit model license and usage rights
    
    2. DEPENDENCY MANAGEMENT
       ✓ Software Composition Analysis (SCA)
       ✓ Regular dependency updates
       ✓ Pin specific versions
       ✓ Security advisories monitoring
       ✓ SBOM (Software Bill of Materials)
    
    3. PLUGIN SECURITY
       ✓ Whitelist approved plugins only
       ✓ Code review all plugins
       ✓ Sandbox plugin execution
       ✓ Minimal permissions (least privilege)
       ✓ Regular security audits
    
    4. VENDOR ASSESSMENT
       ✓ Security questionnaires
       ✓ SOC 2 / ISO 27001 certification
       ✓ Data processing agreements
       ✓ Incident response procedures
       ✓ Regular vendor audits
    
    5. SECURE DEVELOPMENT
       ✓ Internal model hosting (not external API)
       ✓ Private model fine-tuning
       ✓ Network segmentation
       ✓ Data loss prevention (DLP)
       ✓ Audit logging of all external calls
    
    6. MONITORING
       ✓ Track all third-party dependencies
       ✓ Monitor for security advisories
       ✓ Detect anomalous behavior
       ✓ Regular penetration testing
       ✓ Incident response plan
    
    SUPPLY CHAIN SECURITY CHECKLIST:
    
    Models & Frameworks:
    - [ ] Models from official sources only (OpenAI, Anthropic, etc.)
    - [ ] Verify model signatures
    - [ ] Review model training data sources
    - [ ] Check for known vulnerabilities
    - [ ] Audit model license compliance
    
    Dependencies:
    - [ ] Use requirements.txt / package-lock.json
    - [ ] Pin specific versions
    - [ ] Run Snyk / Dependabot
    - [ ] Regular security updates
    - [ ] SBOM generation
    
    Plugins & Extensions:
    - [ ] Whitelist approved plugins
    - [ ] Code review before use
    - [ ] Minimal permissions granted
    - [ ] Sandboxed execution
    - [ ] Regular audits
    
    Third-Party Services:
    - [ ] Vendor security assessment
    - [ ] Data processing agreement
    - [ ] Compliance certifications
    - [ ] Incident response SLA
    - [ ] Regular security reviews
    
    PAYPAL-SPECIFIC REQUIREMENTS:
    ✓ NEVER send production data to external LLMs without approval
    ✓ Use Azure OpenAI (not public OpenAI) for compliance
    ✓ Private model deployment for sensitive use cases
    ✓ All plugins must pass security review
    ✓ Vendor risk assessment for all AI services
    ✓ Data residency requirements (PCI-DSS)
    
    REAL-WORLD INCIDENTS:
    - SolarWinds (2020): Supply chain attack via compromised update
    - PyTorch Compromised (2023): Malicious torchvision dependency
    - NPM Package Attacks: Typosquatting and malicious packages
    - Hugging Face Model Risks: Unverified models with malicious code
    
    TOOLS FOR SUPPLY CHAIN SECURITY:
    - Snyk: Vulnerability scanning
    - Dependabot: Automated dependency updates
    - Trivy: Container and dependency scanning
    - OWASP Dependency-Check: Java/Python dependencies
    - Syft: SBOM generation
    """)
    
    print("\n" + "=" * 70)
    print("KEY TAKEAWAY")
    print("=" * 70)
    print("""
    Supply chain is the weakest link in LLM security.
    
    Defense requires:
    - Verify model provenance
    - Audit all dependencies
    - Whitelist plugins only
    - Vendor security assessments
    - Continuous monitoring
    
    For PayPal: Use private deployments, never external APIs with customer data.
    """)


if __name__ == "__main__":
    demonstrate_concept()

