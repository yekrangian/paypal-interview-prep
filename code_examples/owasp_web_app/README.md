# OWASP Top 10 Web Application Security Code Examples

This directory contains comprehensive code examples demonstrating the **OWASP Top 10 (2021)** web application security vulnerabilities and their secure implementations.

## 📁 File Structure

Each file covers one OWASP Top 10 category with both vulnerable and secure code examples:

| File | Category | Description |
|------|----------|-------------|
| **A01_broken_access_control.py** | Broken Access Control | IDOR, missing authorization, path traversal |
| **A02_cryptographic_failures.py** | Cryptographic Failures | Weak encryption, plaintext storage, insecure hashing |
| **A03_injection.py** | Injection | SQL injection, command injection, LDAP injection |
| **A04_insecure_design.py** | Insecure Design | Business logic flaws, race conditions, missing validation |
| **A05_security_misconfiguration.py** | Security Misconfiguration | Debug mode, missing headers, default credentials |
| **A06_vulnerable_components.py** | Vulnerable Components | Outdated libraries, dependency scanning, SBOM |
| **A07_authentication_failures.py** | Authentication Failures | Weak passwords, brute force, session management |
| **A08_integrity_failures.py** | Integrity Failures | Insecure deserialization, unsigned updates, JWT issues |
| **A09_logging_monitoring.py** | Logging & Monitoring | Missing logs, insufficient monitoring, no alerting |
| **A10_ssrf.py** | Server-Side Request Forgery | Internal service access, cloud metadata, DNS rebinding |

## 🎯 Purpose

These examples are designed for:
- **Interview Preparation** - Understanding security vulnerabilities for cybersecurity roles
- **Security Training** - Learning secure coding practices
- **Code Review** - Recognizing vulnerable patterns
- **Penetration Testing** - Understanding attack vectors

## 📖 How to Use

### 1. Study Each File

Each file contains:
- **Vulnerability Description** - What the vulnerability is and why it's dangerous
- **Vulnerable Code Examples** - Real-world patterns to avoid
- **Attack Scenarios** - How attackers exploit the vulnerability
- **Secure Code Examples** - Best practices and fixes
- **Real-World Breaches** - Famous incidents related to the vulnerability
- **Prevention Best Practices** - Comprehensive security guidelines

### 2. Run Examples (Educational Only)

**⚠️ WARNING**: These examples contain intentionally vulnerable code. **NEVER** use in production!

```bash
# Example: Run A03 (Injection) examples
python A03_injection.py
```

### 3. Compare Vulnerable vs Secure

Each file has two sections:
- **VULNERABLE CODE** - Demonstrates the vulnerability
- **SECURE CODE** - Shows the correct implementation

Look for these markers in the code:
```python
# --- Vulnerable Code ---
# VULNERABILITY: Description of the issue
# Attack: How it can be exploited
# Impact: What damage can be done

# --- Secure Code ---
# SECURE: Description of the fix
# Defense: How it protects against attacks
```

## 🔒 Key Security Concepts

### Top Priorities

1. **Input Validation** - Never trust user input
2. **Authentication** - Verify identity properly
3. **Authorization** - Check permissions on every request
4. **Encryption** - Protect data at rest and in transit
5. **Logging** - Monitor and detect attacks

### Defense in Depth

These examples demonstrate multiple layers of security:
- Application layer security
- Database security
- Network security
- Infrastructure security

## 📚 Learning Path

### Beginner
Start with these fundamentals:
1. **A03 - Injection** (SQL injection basics)
2. **A01 - Broken Access Control** (Authorization basics)
3. **A07 - Authentication Failures** (Authentication basics)

### Intermediate
Progress to these topics:
4. **A02 - Cryptographic Failures** (Encryption and hashing)
5. **A05 - Security Misconfiguration** (Secure configuration)
6. **A09 - Logging & Monitoring** (Detection and response)

### Advanced
Master complex vulnerabilities:
7. **A04 - Insecure Design** (Business logic security)
8. **A08 - Integrity Failures** (Deserialization, signing)
9. **A10 - SSRF** (Advanced attack vectors)
10. **A06 - Vulnerable Components** (Supply chain security)

## 🛠️ Tools Referenced

These files reference industry-standard security tools:

**Scanning & Testing:**
- OWASP ZAP
- Burp Suite
- Nikto
- SQLMap
- Nmap

**Dependency Scanning:**
- Safety (Python)
- Snyk
- OWASP Dependency-Check
- Trivy

**SIEM & Monitoring:**
- ELK Stack
- Splunk
- Datadog
- AWS CloudWatch

## 🌐 Real-World Breaches

Each file includes real-world breach examples:
- **Equifax (2017)** - Unpatched Struts (A06), Poor monitoring (A09)
- **Capital One (2019)** - SSRF to AWS metadata (A10)
- **Uber (2016)** - Insecure deserialization (A08)
- **Target (2013)** - Poor logging & monitoring (A09)
- **SolarWinds (2020)** - Supply chain attack (A08)

## ✅ Security Checklist

Use this checklist when reviewing code:

### Authentication & Authorization
- [ ] Strong password policies enforced
- [ ] MFA enabled for admin accounts
- [ ] Authorization checks on every endpoint
- [ ] Session management secure
- [ ] Rate limiting implemented

### Data Protection
- [ ] All sensitive data encrypted
- [ ] Passwords hashed with bcrypt
- [ ] HTTPS enforced
- [ ] Secure cookie flags set
- [ ] PII protected

### Input Validation
- [ ] Parameterized queries used
- [ ] Input validation on all fields
- [ ] Output encoding applied
- [ ] File uploads restricted
- [ ] Command injection prevented

### Configuration
- [ ] Debug mode disabled in production
- [ ] Security headers configured
- [ ] Default credentials changed
- [ ] Error messages generic
- [ ] Unnecessary features disabled

### Monitoring
- [ ] Security events logged
- [ ] Centralized logging configured
- [ ] Real-time alerting enabled
- [ ] Incident response plan ready

## 🔗 Additional Resources

**OWASP Resources:**
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

**Security Standards:**
- [PCI DSS](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)

**Training Platforms:**
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## ⚠️ Legal Disclaimer

**EDUCATIONAL USE ONLY**

These code examples contain intentionally vulnerable code for educational purposes. They are designed to:
- Teach security concepts
- Prepare for cybersecurity interviews
- Train developers on secure coding

**DO NOT:**
- Use in production applications
- Deploy on public-facing servers
- Use for unauthorized testing
- Exploit real systems

Always obtain proper authorization before conducting security testing.

## 📝 Interview Tips

When discussing these vulnerabilities in interviews:

1. **Understand the Root Cause** - Don't just memorize, understand why it's vulnerable
2. **Know the Impact** - Explain business impact, not just technical details
3. **Propose Multiple Defenses** - Show defense-in-depth thinking
4. **Reference Real Breaches** - Demonstrate awareness of real-world incidents
5. **Know the Tools** - Be familiar with testing and remediation tools

### Sample Interview Questions

**"How would you prevent SQL injection?"**
- Parameterized queries/prepared statements
- Input validation and sanitization
- Least privilege database accounts
- Web Application Firewall (WAF)
- Regular security testing

**"What's the difference between authentication and authorization?"**
- Authentication: Verify identity (who you are)
- Authorization: Verify permissions (what you can do)
- Both are needed for security

**"How do you secure sensitive data at rest?"**
- Encryption (AES-256)
- Secure key management
- Database encryption
- Access controls
- Audit logging

## 🤝 Contributing

Found an issue or want to add more examples? This is for educational purposes in the PayPal interview preparation package.

## 📄 License

These code examples are provided for educational purposes only. Use at your own risk.

---

**Created for PayPal Staff Cybersecurity Engineer Interview Preparation**

Good luck with your interview! 🚀🔒
