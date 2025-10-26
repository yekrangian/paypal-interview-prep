# OWASP Top 10 for LLM Applications - Code Examples

This directory contains comprehensive code examples demonstrating the **OWASP Top 10 for Large Language Model (LLM) Applications (2023)** vulnerabilities and their secure implementations.

---

## 📁 File Structure

Each file covers one OWASP LLM Top 10 category with both vulnerable and secure code examples:

| File | Category | Description |
|------|----------|-------------|
| **LLM01_prompt_injection.py** | Prompt Injection | System instruction override, jailbreaking, indirect injection |
| **LLM02_insecure_output_handling.py** | Insecure Output Handling | Unvalidated LLM outputs, code injection, XSS from LLM |
| **LLM03_training_data_poisoning.py** | Training Data Poisoning | Compromised training data, backdoors, bias injection |
| **LLM04_model_dos.py** | Model Denial of Service | Resource exhaustion, context overflow, API abuse |
| **LLM05_supply_chain.py** | Supply Chain Vulnerabilities | Compromised models, malicious plugins, untrusted datasets |
| **LLM06_sensitive_info_disclosure.py** | Sensitive Information Disclosure | PII leakage, training data extraction, credential exposure |
| **LLM07_insecure_plugin_design.py** | Insecure Plugin Design | Vulnerable LLM extensions, unvalidated inputs to plugins |
| **LLM08_excessive_agency.py** | Excessive Agency | Over-privileged LLM actions, unauthorized operations |
| **LLM09_overreliance.py** | Overreliance | Blind trust in LLM outputs, hallucination handling |
| **LLM10_model_theft.py** | Model Theft | Model extraction, intellectual property theft, API abuse |

---

## 🎯 Purpose

These examples are designed for:
- **PayPal Interview Preparation** - Understanding AI/LLM security risks
- **LLM Security Training** - Learning secure LLM integration patterns
- **Security Reviews** - Identifying vulnerable LLM implementations
- **AI Product Security** - Building secure AI-powered applications

---

## 🚨 Critical Context: Why LLM Security Matters at PayPal

### PayPal's LLM Use Cases
- **Customer Support Chatbots** - Handling payment queries, account information
- **Fraud Detection** - AI-powered transaction analysis
- **Code Review Assistants** - Internal security tools
- **Document Processing** - Extracting payment information from documents
- **Voice Assistants** - Payment commands via voice

### Risk Landscape
- **Financial Impact:** Direct access to payment systems
- **PII Exposure:** Customer data, payment information, transaction history
- **Regulatory:** GDPR, PCI-DSS compliance requirements
- **Trust:** PayPal's reputation depends on secure AI

---

## 📖 How to Use

### 1. Study Each File

Each file contains:
- **Vulnerability Description** - What makes LLM applications vulnerable
- **Vulnerable Code Examples** - Real-world insecure patterns
- **Attack Scenarios** - How attackers exploit LLM systems
- **Secure Code Examples** - Best practices and mitigations
- **Real-World Incidents** - Documented LLM security breaches
- **Prevention Best Practices** - Comprehensive security guidelines

### 2. Understand Attack Vectors

**⚠️ WARNING**: These examples demonstrate LLM security risks. **NEVER** use vulnerable patterns in production!

### 3. Compare Vulnerable vs Secure

Each file has two sections:
- **VULNERABLE CODE** - Demonstrates the security risk
- **SECURE CODE** - Shows the correct implementation

Look for these markers:
```python
# --- VULNERABLE CODE ---
# VULNERABILITY: Description of the issue
# ATTACK: How it can be exploited
# IMPACT: What damage can be done

# --- SECURE CODE ---
# SECURE: Description of the fix
# DEFENSE: How it protects against attacks
```

---

## 🔒 Key LLM Security Concepts

### Core Principles

1. **Never Trust LLM Output** - Always validate and sanitize
2. **Least Privilege** - Limit LLM capabilities and access
3. **Input Validation** - Sanitize prompts before processing
4. **Output Filtering** - Scan responses for sensitive data
5. **Context Isolation** - Separate system prompts from user inputs
6. **Monitoring** - Track usage patterns and anomalies
7. **Human in the Loop** - Critical decisions require human approval

### Defense in Depth for LLM Applications

```
User Input
    ↓
[Input Validation & Sanitization]
    ↓
[Prompt Injection Detection]
    ↓
[Structured Prompt Construction]
    ↓
[LLM Processing with Guardrails]
    ↓
[Output Filtering & Validation]
    ↓
[PII Redaction]
    ↓
[Action Authorization Checks]
    ↓
[Audit Logging]
    ↓
Safe Response to User
```

---

## 📚 Learning Path

### Beginner - Start Here
1. **LLM01 - Prompt Injection** (Most critical, easiest to understand)
2. **LLM06 - Sensitive Information Disclosure** (Data protection basics)
3. **LLM08 - Excessive Agency** (Authorization and control)

### Intermediate
4. **LLM02 - Insecure Output Handling** (Output validation)
5. **LLM04 - Model DoS** (Resource management)
6. **LLM07 - Insecure Plugin Design** (Extension security)

### Advanced
7. **LLM03 - Training Data Poisoning** (Supply chain security)
8. **LLM05 - Supply Chain Vulnerabilities** (Third-party risks)
9. **LLM09 - Overreliance** (System design considerations)
10. **LLM10 - Model Theft** (IP protection)

---

## 🛠️ Tools & Technologies Referenced

### LLM Platforms
- **OpenAI GPT-4/3.5** - API integration examples
- **Anthropic Claude** - Alternative LLM provider
- **Azure OpenAI** - Enterprise deployment
- **AWS Bedrock** - AWS managed LLM service
- **Google PaLM** - Google's LLM platform

### Security Tools
- **LLM Guardrails** - Input/output filtering
- **Prompt Shields** - Azure's prompt injection detection
- **Lakera Guard** - LLM security platform
- **Rebuff** - Prompt injection detection
- **NeMo Guardrails** - NVIDIA's safety toolkit

### Monitoring & Detection
- **LangSmith** - LLM observability
- **Weights & Biases** - Model monitoring
- **Arize AI** - ML observability
- **WhyLabs** - ML monitoring

---

## 🌐 Real-World LLM Security Incidents

### Notable Breaches & Vulnerabilities

#### 1. ChatGPT Data Breach (March 2023)
**Issue:** Redis bug exposed chat histories to other users
**Impact:** Personal data, payment information exposed
**Lesson:** Even OpenAI struggles with data isolation

#### 2. Bing Chat Jailbreaks (February 2023)
**Issue:** Prompt injection bypassing safety guidelines
**Attack:** "Ignore previous instructions" patterns
**Lesson:** System prompts are not security boundaries

#### 3. Samsung Confidential Data Leak (April 2023)
**Issue:** Engineers pasting sensitive code into ChatGPT
**Impact:** Source code, internal documentation exposed
**Lesson:** LLM providers store and learn from inputs

#### 4. Chevrolet Chatbot Manipulation (December 2023)
**Issue:** Chatbot convinced to sell cars for $1
**Attack:** Social engineering + prompt injection
**Lesson:** Don't give LLMs transactional authority

#### 5. GitHub Copilot Secrets Exposure (2021)
**Issue:** AI suggesting hardcoded API keys from training data
**Impact:** Credentials embedded in suggestions
**Lesson:** Training data must be sanitized

---

## ✅ LLM Security Checklist

Use this when reviewing LLM integrations:

### Input Security
- [ ] Input validation on all prompts
- [ ] Length limits enforced
- [ ] Prompt injection detection
- [ ] Rate limiting per user/API key
- [ ] Content filtering (profanity, malicious patterns)

### Prompt Engineering
- [ ] System prompts separated from user inputs
- [ ] Delimiter tokens used
- [ ] Structured prompt formats
- [ ] Role definitions clear
- [ ] Examples don't contain sensitive data

### Output Security
- [ ] Output validation and sanitization
- [ ] PII detection and redaction
- [ ] Code execution disabled by default
- [ ] SQL/command injection prevention
- [ ] XSS prevention for web outputs

### Authorization & Control
- [ ] Function calling restricted to allowlist
- [ ] Confirmation required for sensitive actions
- [ ] MFA for high-value operations
- [ ] Least privilege for LLM permissions
- [ ] Human approval for critical decisions

### Data Protection
- [ ] No PII in training data
- [ ] Customer data not sent to external LLMs
- [ ] Encryption in transit (TLS 1.3)
- [ ] Encryption at rest
- [ ] Data retention policies enforced

### Monitoring & Logging
- [ ] All LLM interactions logged
- [ ] Anomaly detection enabled
- [ ] Cost monitoring (token usage)
- [ ] Error rate tracking
- [ ] Security event alerting

### Model Security
- [ ] Model provenance verified
- [ ] Dependencies scanned for vulnerabilities
- [ ] Model signing and verification
- [ ] Version control for models
- [ ] Rollback capability

---

## 🎯 PayPal-Specific Considerations

### PCI-DSS Compliance for LLM
- **Never send full credit card numbers to external LLMs**
- **Tokenize payment data before LLM processing**
- **Mask PAN (Primary Account Number) in logs**
- **No cardholder data in training datasets**
- **Audit trail for all LLM access to payment data**

### GDPR Compliance
- **Right to deletion** - Remove user data from LLM context
- **Purpose limitation** - Only use data for stated purposes
- **Data minimization** - Send minimum data to LLM
- **Consent** - User agreement for AI processing
- **Breach notification** - 72-hour reporting if LLM exposes data

### Financial Fraud Considerations
- **Transaction verification** - Never auto-approve based solely on LLM
- **Anomaly detection** - Flag unusual LLM-driven patterns
- **Multi-factor verification** - Confirm high-value AI decisions
- **Audit trail** - Complete history of LLM recommendations

---

## 🎓 Interview Preparation Tips

### Key Talking Points

**When discussing LLM security in interviews:**

1. **Understand the Threat Model**
   - What data does the LLM have access to?
   - What actions can it perform?
   - Who can interact with it?
   - What's the blast radius if compromised?

2. **Know the Defenses**
   - Input validation and sanitization
   - Output filtering
   - Function calling restrictions
   - Authorization checks
   - Monitoring and alerting

3. **Reference Real Incidents**
   - ChatGPT data breach
   - Bing Chat jailbreaks
   - Samsung data leak
   - Shows you follow security news

4. **Demonstrate Depth**
   - Explain prompt injection vs regular injection
   - Discuss defense-in-depth approach
   - Show understanding of business context
   - Balance security with usability

### Sample Interview Questions

**"How would you secure an LLM-powered customer support chatbot for PayPal?"**

**Strong Answer Structure:**
1. **Threat Model** - Prompt injection, data leakage, unauthorized actions
2. **Input Security** - Validation, injection detection, rate limiting
3. **Output Security** - PII filtering, validation before action
4. **Authorization** - Read-only by default, confirmation for transactions
5. **Monitoring** - Audit logs, anomaly detection, alerting
6. **Compliance** - PCI-DSS, GDPR considerations

**"What's the difference between prompt injection and SQL injection?"**
- **SQL Injection:** Malicious SQL in data
- **Prompt Injection:** Malicious instructions in prompts
- **Similarity:** Both exploit insufficient input validation
- **Difference:** Prompt injection is semantic, harder to detect with patterns

**"How do you prevent LLM from exposing sensitive customer data?"**
- Don't send sensitive data to LLM
- PII redaction before processing
- Output filtering and scanning
- Separate models for different sensitivity levels
- Data retention controls

---

## 🔗 Additional Resources

### Official OWASP Resources
- **OWASP Top 10 for LLM Applications:** https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **OWASP LLM AI Security & Governance Checklist:** https://owasp.org/www-project-ai-security-and-privacy-guide/

### LLM Security Research
- **Anthropic's Red Teaming Results:** https://www.anthropic.com/research
- **OpenAI's Safety Best Practices:** https://platform.openai.com/docs/guides/safety-best-practices
- **Microsoft's Responsible AI:** https://www.microsoft.com/en-us/ai/responsible-ai
- **Google's AI Principles:** https://ai.google/principles/

### LLM Security Tools
- **NVIDIA NeMo Guardrails:** https://github.com/NVIDIA/NeMo-Guardrails
- **Rebuff (Prompt Injection Detection):** https://github.com/protectai/rebuff
- **Garak (LLM Vulnerability Scanner):** https://github.com/leondz/garak
- **LangChain Security:** https://python.langchain.com/docs/security

### Security News & Blogs
- **AI Security News:** https://aisecuritynews.com/
- **HiddenLayer (AI/ML Security):** https://hiddenlayer.com/blog/
- **Trail of Bits AI Security:** https://blog.trailofbits.com/category/artificial-intelligence/

---

## ⚠️ Legal & Ethical Disclaimer

**EDUCATIONAL USE ONLY**

These code examples contain intentionally vulnerable LLM implementations for educational purposes. They are designed to:
- Teach LLM security concepts
- Prepare for cybersecurity interviews
- Train developers on secure AI practices

**DO NOT:**
- Deploy vulnerable code in production
- Use on systems with real user data
- Test against unauthorized systems
- Expose to untrusted users
- Use for malicious purposes

**RESPONSIBLE AI DEVELOPMENT:**
- Always obtain proper authorization before testing
- Follow responsible disclosure for vulnerabilities
- Respect user privacy and data protection laws
- Consider ethical implications of AI systems
- Build with safety and security in mind

---

## 📊 File Statistics

**Total Examples:** 10 vulnerability categories
**Code Samples:** 60+ vulnerable/secure pairs
**Real-World Incidents:** 15+ documented cases
**Security Patterns:** 30+ secure implementations
**Study Time:** 15-20 hours of material

---

## 🎬 Getting Started

### Prerequisites
```bash
# Install required packages
pip install openai anthropic langchain tiktoken

# Set environment variables (never hardcode!)
export OPENAI_API_KEY="your-key-here"
export ANTHROPIC_API_KEY="your-key-here"
```

### Running Examples
```bash
# Navigate to directory
cd /Users/yekrangian/Codes/paypal-job/code_examples/owasp_llm

# Run specific vulnerability example
python LLM01_prompt_injection.py

# Study the code
cat LLM01_prompt_injection.py | less
```

### Study Approach
1. **Read the file header** - Understand the vulnerability
2. **Review vulnerable examples** - See what NOT to do
3. **Study attack scenarios** - Understand exploitation
4. **Learn secure patterns** - See correct implementations
5. **Practice explaining** - Teach concepts to others

---

## 🚀 Next Steps After Studying

### Hands-On Practice
1. **Build a secure chatbot** - Apply learned concepts
2. **Red team an LLM app** - Try prompt injection attacks
3. **Implement guardrails** - Add security layers
4. **Create detection rules** - Build monitoring

### Interview Preparation
1. **Prepare 3-5 LLM security stories** using STAR method
2. **Practice explaining prompt injection** to non-technical stakeholders
3. **Discuss LLM security in PayPal context** (payments, PII)
4. **Review recent LLM security news** (show you're current)

### Continue Learning
1. Complete LangChain security course
2. Follow OWASP LLM project updates
3. Read AI security research papers
4. Join AI security community (Discord, Twitter)

---

## 💡 Key Takeaways

### For Interview Success

**Remember these core principles:**

1. **LLMs are not security boundaries** - System prompts can be overridden
2. **Always validate outputs** - Never trust LLM responses for security decisions
3. **Least privilege** - Limit LLM capabilities to minimum necessary
4. **Defense in depth** - Multiple layers of protection
5. **Privacy first** - Minimize sensitive data exposure to LLMs
6. **Human oversight** - Critical decisions need human approval
7. **Monitor everything** - LLM interactions must be logged and analyzed

**Staff-Level Expectations:**
- Not just finding LLM vulnerabilities
- **Designing secure AI architectures**
- **Building guardrails and safety systems**
- **Establishing LLM security policies**
- **Training teams on AI security**
- **Balancing innovation with security**

---

## 🎯 Interview Question Bank

### Technical Questions

**Q: How would you prevent prompt injection in a customer service chatbot?**
<details>
<summary>Answer Framework</summary>

1. **Input Layer:** Validation, length limits, pattern detection
2. **Prompt Construction:** Structured formats, delimiters, role separation
3. **Output Layer:** Content filtering, PII redaction, validation
4. **Monitoring:** Anomaly detection, logging, alerting
5. **Response:** "I'd implement defense-in-depth with multiple validation layers..."
</details>

**Q: What's the difference between direct and indirect prompt injection?**
<details>
<summary>Answer Framework</summary>

- **Direct:** User directly manipulates prompt ("Ignore instructions")
- **Indirect:** Malicious content in retrieved data (poisoned documents)
- **Example:** Email with hidden instructions for email assistant
- **Defense:** Sanitize all external content, tag trusted vs untrusted
</details>

**Q: How do you balance LLM utility with security?**
<details>
<summary>Answer Framework</summary>

- Risk-based approach (low-risk = more capability, high-risk = more restrictions)
- Tiered access (public chatbot vs internal tool vs payment system)
- Progressive enhancement (start restrictive, gradually enable features)
- A/B testing security controls
- User feedback on false positives
</details>

---

## 📈 Metrics to Track

### LLM Security Posture
- **Prompt injection detection rate** (TP/FP)
- **PII leakage incidents** (zero target)
- **Unauthorized action attempts** (monitor trend)
- **Token usage anomalies** (detect abuse)
- **Response time impact** (security overhead)
- **User satisfaction** (security vs usability)

---

## ✅ Completion Checklist

Track your progress through all 10 vulnerabilities:

- [ ] **LLM01: Prompt Injection** - System instruction override
- [ ] **LLM02: Insecure Output Handling** - Unvalidated outputs
- [ ] **LLM03: Training Data Poisoning** - Compromised training
- [ ] **LLM04: Model DoS** - Resource exhaustion
- [ ] **LLM05: Supply Chain** - Third-party risks
- [ ] **LLM06: Sensitive Info Disclosure** - Data leakage
- [ ] **LLM07: Insecure Plugin Design** - Extension vulnerabilities
- [ ] **LLM08: Excessive Agency** - Over-privileged actions
- [ ] **LLM09: Overreliance** - Blind trust in outputs
- [ ] **LLM10: Model Theft** - IP protection

---

**Created for PayPal Staff Cybersecurity Engineer Interview Preparation**

Good luck with securing AI/LLM systems at PayPal! 🚀🤖🔒

*Remember: The best AI security engineers build systems that are both powerful AND safe. Show them you can do both.*

