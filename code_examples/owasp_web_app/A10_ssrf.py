"""
OWASP A10:2021 - Server-Side Request Forgery (SSRF)
====================================================

SSRF flaws occur when a web application fetches a remote resource without
validating the user-supplied URL. It allows an attacker to coerce the
application to send a crafted request to an unexpected destination, even
when protected by a firewall, VPN, or another type of network ACL.

Common attack scenarios:
- Access internal services (metadata endpoints, admin panels)
- Port scanning internal network
- Reading files via file:// protocol
- Cloud metadata exploitation (AWS, Azure, GCP)
- Bypassing IP whitelists
"""

from flask import Flask, request, jsonify
import requests
import urllib.parse
import ipaddress
import socket

app = Flask(__name__)

# ============================================================================
# VULNERABLE CODE EXAMPLES
# ============================================================================

# Example 1: Basic SSRF - URL Parameter
@app.route('/api/fetch_url', methods=['POST'])
def fetch_url_vulnerable():
    """
    VULNERABILITY: No URL validation
    
    Attack: ?url=http://localhost:6379/  (Access internal Redis)
            ?url=http://169.254.169.254/latest/meta-data/  (AWS metadata)
    Impact: Access to internal services, cloud metadata
    """
    data = request.get_json()
    url = data.get('url')
    
    # No validation - fetches ANY URL!
    try:
        response = requests.get(url, timeout=5)
        return jsonify({
            'status_code': response.status_code,
            'content': response.text
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Example 2: SSRF via Image/PDF URL
@app.route('/api/generate_thumbnail', methods=['POST'])
def generate_thumbnail_vulnerable():
    """
    VULNERABILITY: SSRF via image URL
    
    Attack: ?image_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    Impact: AWS credentials theft
    """
    data = request.get_json()
    image_url = data.get('image_url')
    
    # Fetches image without validation
    response = requests.get(image_url)
    
    # Process image...
    return jsonify({
        'message': 'Thumbnail generated',
        'size': len(response.content)
    })


# Example 3: SSRF via Redirect Following
@app.route('/api/check_website', methods=['POST'])
def check_website_vulnerable():
    """
    VULNERABILITY: Follows redirects without validation
    
    Attack: Attacker's server redirects to internal service
    Impact: Bypass URL validation via redirect
    """
    data = request.get_json()
    url = data.get('url')
    
    # Follows redirects blindly!
    response = requests.get(url, 
                           allow_redirects=True,  # Vulnerable!
                           timeout=5)
    
    return jsonify({
        'status': 'reachable',
        'final_url': response.url,
        'status_code': response.status_code
    })


# Example 4: SSRF via XML External Entity (XXE)
@app.route('/api/parse_xml', methods=['POST'])
def parse_xml_vulnerable():
    """
    VULNERABILITY: XXE leads to SSRF
    
    Attack: 
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
    <data>&xxe;</data>
    
    Impact: Access internal resources via XML
    """
    import xml.etree.ElementTree as ET
    
    xml_data = request.data
    
    # Parse XML without disabling external entities
    tree = ET.fromstring(xml_data)
    
    return jsonify({
        'parsed': True,
        'data': tree.text
    })


# Example 5: Blind SSRF
@app.route('/api/webhook', methods=['POST'])
def webhook_vulnerable():
    """
    VULNERABILITY: Blind SSRF - no response shown
    
    Attack: webhook_url=http://internal-admin.local/delete_all
    Impact: Trigger actions on internal services
    """
    data = request.get_json()
    webhook_url = data.get('webhook_url')
    
    # Sends POST request without validation
    # Even if response isn't returned, attack succeeds
    try:
        requests.post(webhook_url, json={'event': 'user_created'}, timeout=5)
        return jsonify({'message': 'Webhook sent'})
    except:
        # Still reveals if service is reachable via timing
        return jsonify({'message': 'Webhook sent'})


# Example 6: SSRF via File Upload (SVG)
@app.route('/api/upload_svg', methods=['POST'])
def upload_svg_vulnerable():
    """
    VULNERABILITY: SVG file can trigger SSRF
    
    Attack: Upload SVG with embedded URL:
    <svg><image href="http://169.254.169.254/latest/meta-data/"/></svg>
    
    Impact: Server fetches URL when processing SVG
    """
    file = request.files.get('file')
    
    # Process SVG without validation
    # Image processing libraries may fetch external URLs
    content = file.read()
    
    return jsonify({'message': 'SVG uploaded'})


# ============================================================================
# SECURE CODE EXAMPLES
# ============================================================================

# Example 1: SECURE - URL Validation with Whitelist
ALLOWED_DOMAINS = [
    'api.example.com',
    'cdn.example.com'
]

BLOCKED_IPS = [
    ipaddress.ip_network('10.0.0.0/8'),      # Private
    ipaddress.ip_network('172.16.0.0/12'),   # Private
    ipaddress.ip_network('192.168.0.0/16'),  # Private
    ipaddress.ip_network('127.0.0.0/8'),     # Loopback
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local (AWS metadata!)
    ipaddress.ip_network('::1/128'),         # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),        # IPv6 private
]


def is_safe_url(url):
    """
    SECURE: Validate URL safety
    
    Defense: Multiple layers of validation
    """
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Only allow HTTP/HTTPS
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP/HTTPS allowed"
        
        # Check if domain is in whitelist
        hostname = parsed.hostname
        if hostname not in ALLOWED_DOMAINS:
            return False, "Domain not in whitelist"
        
        # Resolve hostname to IP
        try:
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
            
            # Check if IP is in blocked ranges
            for blocked_network in BLOCKED_IPS:
                if ip in blocked_network:
                    return False, f"IP {ip} is in blocked range"
            
        except socket.gaierror:
            return False, "Cannot resolve hostname"
        
        # Check for unusual ports
        port = parsed.port
        if port and port not in [80, 443]:
            return False, "Only ports 80 and 443 allowed"
        
        return True, "URL is safe"
        
    except Exception as e:
        return False, f"Invalid URL: {str(e)}"


@app.route('/api/fetch_url_secure', methods=['POST'])
def fetch_url_secure():
    """
    SECURE: URL validation before fetching
    
    Defense: Whitelist domains, block private IPs
    """
    data = request.get_json()
    url = data.get('url')
    
    # Validate URL
    is_safe, message = is_safe_url(url)
    if not is_safe:
        return jsonify({'error': message}), 400
    
    try:
        # Disable redirects (prevent bypass via redirect)
        response = requests.get(
            url, 
            timeout=5,
            allow_redirects=False,  # Important!
            headers={'User-Agent': 'MyApp/1.0'}
        )
        
        # Limit response size
        MAX_SIZE = 1024 * 1024  # 1MB
        if int(response.headers.get('Content-Length', 0)) > MAX_SIZE:
            return jsonify({'error': 'Response too large'}), 400
        
        return jsonify({
            'status_code': response.status_code,
            'content_length': len(response.content),
            'content_type': response.headers.get('Content-Type')
            # Don't return full content - limit exposure
        })
        
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout'}), 500
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Request failed'}), 500


# Example 2: SECURE - DNS Rebinding Protection
class SSRFProtectedFetcher:
    """
    SECURE: Protection against DNS rebinding attacks
    
    Defense: Re-validate IP after DNS resolution
    """
    
    @staticmethod
    def fetch_url(url):
        """Fetch URL with DNS rebinding protection"""
        
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        
        # First DNS resolution
        try:
            initial_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            raise ValueError("Cannot resolve hostname")
        
        # Validate IP is not private
        ip = ipaddress.ip_address(initial_ip)
        for blocked_network in BLOCKED_IPS:
            if ip in blocked_network:
                raise ValueError(f"IP {ip} is blocked")
        
        # Custom resolver to prevent DNS rebinding
        session = requests.Session()
        
        # Make request
        response = session.get(
            url,
            timeout=5,
            allow_redirects=False
        )
        
        # Second DNS resolution (check for DNS rebinding)
        try:
            final_ip = socket.gethostbyname(hostname)
            if initial_ip != final_ip:
                raise ValueError("DNS rebinding detected")
        except socket.gaierror:
            raise ValueError("DNS resolution failed")
        
        return response


# Example 3: SECURE - Webhook URL Validation
def validate_webhook_url(url):
    """
    SECURE: Validate webhook URL
    
    Defense: Strict validation for webhooks
    """
    # Must be HTTPS
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https':
        return False, "Webhook must use HTTPS"
    
    # Check domain
    if not parsed.hostname:
        return False, "Invalid hostname"
    
    # Resolve and validate IP
    try:
        ip_str = socket.gethostbyname(parsed.hostname)
        ip = ipaddress.ip_address(ip_str)
        
        # Block private IPs
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False, "Private IPs not allowed"
        
        # Block cloud metadata IPs
        metadata_ip = ipaddress.ip_address('169.254.169.254')
        if ip == metadata_ip:
            return False, "Cloud metadata IP blocked"
            
    except (socket.gaierror, ValueError) as e:
        return False, f"IP validation failed: {e}"
    
    return True, "Valid webhook URL"


@app.route('/api/webhook_secure', methods=['POST'])
def webhook_secure():
    """
    SECURE: Webhook with URL validation
    
    Defense: Validate before sending request
    """
    data = request.get_json()
    webhook_url = data.get('webhook_url')
    
    # Validate URL
    is_valid, message = validate_webhook_url(webhook_url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        # Send with timeout and no redirects
        response = requests.post(
            webhook_url,
            json={'event': 'user_created'},
            timeout=5,
            allow_redirects=False
        )
        
        return jsonify({
            'message': 'Webhook sent',
            'status_code': response.status_code
        })
        
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Webhook timeout'}), 500
    except requests.exceptions.RequestException:
        return jsonify({'error': 'Webhook failed'}), 500


# Example 4: SECURE - Image URL Validation
ALLOWED_IMAGE_DOMAINS = ['cdn.example.com', 'images.example.com']

def validate_image_url(url):
    """Validate image URL"""
    parsed = urllib.parse.urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ['https']:  # HTTPS only
        return False
    
    # Check domain whitelist
    if parsed.hostname not in ALLOWED_IMAGE_DOMAINS:
        return False
    
    # Validate IP
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if ip.is_private or ip.is_loopback:
            return False
    except:
        return False
    
    return True


@app.route('/api/generate_thumbnail_secure', methods=['POST'])
def generate_thumbnail_secure():
    """
    SECURE: Image URL validation
    
    Defense: Whitelist image domains only
    """
    data = request.get_json()
    image_url = data.get('image_url')
    
    if not validate_image_url(image_url):
        return jsonify({'error': 'Invalid image URL'}), 400
    
    try:
        response = requests.get(
            image_url,
            timeout=5,
            allow_redirects=False,
            stream=True  # Don't load entire response
        )
        
        # Verify content type
        content_type = response.headers.get('Content-Type', '')
        if not content_type.startswith('image/'):
            return jsonify({'error': 'Not an image'}), 400
        
        # Limit size
        MAX_SIZE = 10 * 1024 * 1024  # 10MB
        if int(response.headers.get('Content-Length', 0)) > MAX_SIZE:
            return jsonify({'error': 'Image too large'}), 400
        
        return jsonify({'message': 'Thumbnail generated'})
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch image'}), 500


# ============================================================================
# CLOUD METADATA PROTECTION
# ============================================================================

"""
SECURE: Block Cloud Metadata Access

# AWS Metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure Metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# GCP Metadata
http://metadata.google.internal/computeMetadata/v1/

Defense:
1. Block IP 169.254.169.254 in application
2. Use IMDSv2 on AWS (requires token)
3. Network-level blocking (security groups)
4. Monitor for metadata access attempts
"""

# Example: AWS IMDSv2 Configuration
"""
# Launch instance with IMDSv2 required
aws ec2 run-instances \
  --image-id ami-12345678 \
  --instance-type t2.micro \
  --metadata-options \
    HttpTokens=required,\
    HttpPutResponseHopLimit=1

# This requires a token for metadata access:
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
"""


# ============================================================================
# PREVENTION BEST PRACTICES
# ============================================================================

"""
SSRF PREVENTION BEST PRACTICES:

URL Validation:
✅ Whitelist allowed domains
✅ Block private IP ranges (10.x, 192.168.x, 127.x)
✅ Block link-local (169.254.x.x - cloud metadata!)
✅ Only allow HTTP/HTTPS schemes
✅ Disable redirects or validate redirect targets
✅ Validate both hostname and resolved IP

Network Security:
✅ Segment internal services
✅ Use firewalls to block internal access
✅ Implement network ACLs
✅ Block metadata endpoints (169.254.169.254)
✅ Use VPC endpoints (AWS)

Application Security:
✅ Use allow lists (not deny lists)
✅ Validate after DNS resolution
✅ Set request timeouts
✅ Limit response sizes
✅ Disable XML external entities
✅ Sanitize SVG files

Cloud Protection:
✅ Use IMDSv2 on AWS
✅ Disable instance metadata if not needed
✅ Use managed identities (Azure)
✅ Implement least privilege IAM roles
✅ Monitor metadata access

Response Handling:
✅ Don't return raw responses
✅ Parse and sanitize content
✅ Log all external requests
✅ Monitor for unusual patterns

CODE CHECKLIST:

✅ Whitelist allowed domains
✅ Block private IP ranges
✅ Block 169.254.169.254 (cloud metadata)
✅ Disable redirects or validate targets
✅ Set request timeouts
✅ Limit response sizes
✅ Validate both hostname and IP
✅ Use HTTPS only for webhooks
✅ Log all external requests
✅ Monitor for SSRF attempts
"""

# ============================================================================
# REAL-WORLD EXAMPLES
# ============================================================================

"""
REAL-WORLD SSRF ATTACKS:

1. Capital One (2019)
   - SSRF to AWS metadata endpoint
   - Stolen IAM credentials
   - 100 million customers affected
   - $80 million fine
   - Attack: http://169.254.169.254/latest/meta-data/iam/security-credentials/

2. Uber (2016)
   - SSRF in PDF generation service
   - Access to internal services
   - 57 million users compromised
   - $148 million settlement

3. Google Cloud (2020)
   - SSRF in Compute Engine
   - $7,500 bug bounty
   - Could access metadata service

4. GitLab (2020)
   - SSRF in Webhook feature
   - Could scan internal network
   - $12,000 bug bounty paid

5. Shopify (2021)
   - SSRF in image processing
   - Access to internal AWS services
   - $25,000 bug bounty

6. Facebook (2020)
   - SSRF in image fetching
   - Internal network scanning possible
   - $31,500 bug bounty

Attack Pattern:
1. Find URL input (webhooks, image URLs, XML, PDF generation)
2. Try internal IPs (127.0.0.1, 192.168.x.x)
3. Try cloud metadata (169.254.169.254)
4. Port scan internal network
5. Access internal services (Redis, ElasticSearch, admin panels)

KEY LESSONS:
- Always validate URL destinations
- Block private IP ranges
- Protect cloud metadata endpoints
- Use IMDSv2 on AWS
- Monitor for SSRF attempts
- Defense in depth (application + network)
"""

# ============================================================================
# TESTING
# ============================================================================

def test_ssrf_protection():
    """Test SSRF protection mechanisms"""
    print("\n=== SSRF Protection Test ===")
    
    malicious_urls = [
        'http://localhost:6379/',
        'http://127.0.0.1/admin',
        'http://192.168.1.1/',
        'http://169.254.169.254/latest/meta-data/',  # AWS metadata
        'file:///etc/passwd',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://evil.com@169.254.169.254/'  # URL obfuscation
    ]
    
    print("Testing protection against malicious URLs:")
    for url in malicious_urls:
        is_safe, msg = is_safe_url(url)
        status = "✅ Blocked" if not is_safe else "❌ Allowed (VULNERABLE!)"
        print(f"  {status}: {url}")


if __name__ == '__main__':
    print("OWASP A10:2021 - Server-Side Request Forgery (SSRF) Examples")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- Basic SSRF vulnerabilities")
    print("- Cloud metadata exploitation")
    print("- DNS rebinding attacks")
    print("- Blind SSRF")
    print("\nSecure implementations include:")
    print("✅ URL whitelist validation")
    print("✅ Private IP blocking")
    print("✅ Cloud metadata protection")
    print("✅ DNS rebinding prevention")
    
    test_ssrf_protection()


