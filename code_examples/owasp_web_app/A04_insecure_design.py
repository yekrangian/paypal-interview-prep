"""
OWASP A04:2021 - Insecure Design
=================================

Insecure design is a broad category representing different weaknesses, expressed as
"missing or ineffective control design." An insecure design cannot be fixed by a
perfect implementation as the required security controls were never created.

Common issues:
- Missing threat modeling
- Business logic flaws
- Lack of security requirements
- Insufficient security architecture
- Missing security controls by design
"""

from flask import Flask, request, jsonify, session
import sqlite3
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = 'change-me'

# ============================================================================
# VULNERABLE CODE - BUSINESS LOGIC FLAWS
# ============================================================================

# Example 1: Unlimited Password Reset Attempts
@app.route('/api/forgot_password', methods=['POST'])
def forgot_password_vulnerable():
    """
    INSECURE DESIGN: No rate limiting or cooling period
    
    Business Logic Flaw: Can request unlimited password resets
    Impact: Email bombing, DoS on email service
    """
    data = request.get_json()
    email = data.get('email')
    
    # No check for recent reset requests!
    # Attacker can flood user's email with reset links
    
    reset_token = secrets.token_urlsafe(16)
    # send_reset_email(email, reset_token)
    
    return jsonify({'message': 'Reset email sent'})


# Example 2: Race Condition in Money Transfer
@app.route('/api/transfer_money', methods=['POST'])
def transfer_money_vulnerable():
    """
    INSECURE DESIGN: No transaction isolation
    
    Business Logic Flaw: Race condition allows negative balance
    Impact: Financial loss, fraud
    """
    data = request.get_json()
    from_account = data.get('from_account')
    to_account = data.get('to_account')
    amount = float(data.get('amount'))
    
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    
    # Check balance
    cursor.execute("SELECT balance FROM accounts WHERE id = ?", (from_account,))
    balance = cursor.fetchone()[0]
    
    # Race condition here! Multiple requests can pass this check
    if balance >= amount:
        # Deduct from sender (not atomic!)
        cursor.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", 
                      (amount, from_account))
        
        # Add to recipient
        cursor.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", 
                      (amount, to_account))
        
        conn.commit()
        return jsonify({'message': 'Transfer successful'})
    
    return jsonify({'error': 'Insufficient funds'}), 400


# Example 3: Missing Purchase Limits
@app.route('/api/purchase', methods=['POST'])
def purchase_vulnerable():
    """
    INSECURE DESIGN: No business rules validation
    
    Business Logic Flaw: Can buy negative or zero quantity
    Impact: Inventory manipulation, financial loss
    """
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = int(data.get('quantity'))  # Can be negative!
    user_id = session.get('user_id')
    
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Get product price
    cursor.execute("SELECT price, stock FROM products WHERE id = ?", (product_id,))
    price, stock = cursor.fetchone()
    
    # No validation of quantity!
    # Negative quantity = refund without returning item
    total_price = price * quantity
    
    # Update inventory (can go negative!)
    cursor.execute("UPDATE products SET stock = stock - ? WHERE id = ?", 
                  (quantity, product_id))
    
    # Charge user (negative = credit user's account!)
    cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?",
                  (total_price, user_id))
    
    conn.commit()
    return jsonify({'total': total_price})


# Example 4: Coupon Code Abuse
@app.route('/api/apply_coupon', methods=['POST'])
def apply_coupon_vulnerable():
    """
    INSECURE DESIGN: Can apply same coupon multiple times
    
    Business Logic Flaw: No single-use enforcement
    Impact: Financial loss, coupon abuse
    """
    data = request.get_json()
    coupon_code = data.get('coupon_code')
    order_id = data.get('order_id')
    
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Check if coupon exists
    cursor.execute("SELECT discount_percent FROM coupons WHERE code = ?", (coupon_code,))
    coupon = cursor.fetchone()
    
    if coupon:
        # Apply discount (no check if already applied!)
        discount = coupon[0]
        cursor.execute("""
            UPDATE orders 
            SET total = total * (1 - ? / 100) 
            WHERE id = ?
        """, (discount, order_id))
        conn.commit()
        
        return jsonify({'message': f'{discount}% discount applied'})
    
    return jsonify({'error': 'Invalid coupon'}), 400


# Example 5: Account Enumeration via Timing
import time

@app.route('/api/login_timing', methods=['POST'])
def login_timing_vulnerable():
    """
    INSECURE DESIGN: Timing attack reveals valid usernames
    
    Business Logic Flaw: Different response times for valid/invalid users
    Impact: Username enumeration
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user:
        # Expensive hash comparison only for valid users
        time.sleep(0.1)  # Simulates bcrypt
        # Check password...
        return jsonify({'error': 'Invalid password'}), 401
    else:
        # Immediate response for invalid users
        return jsonify({'error': 'Invalid username'}), 401


# ============================================================================
# SECURE CODE - PROPER DESIGN
# ============================================================================

# Example 1: SECURE - Rate Limited Password Reset
class PasswordResetThrottler:
    """
    SECURE: Implement cooling-off period
    
    Design: Limit reset requests per email per time period
    """
    def __init__(self):
        self.reset_attempts = {}
    
    def can_request_reset(self, email):
        """Check if reset can be requested"""
        now = datetime.now()
        
        if email in self.reset_attempts:
            last_request = self.reset_attempts[email]
            
            # Must wait 15 minutes between requests
            cooloff_period = timedelta(minutes=15)
            if now - last_request < cooloff_period:
                remaining = cooloff_period - (now - last_request)
                return False, remaining.seconds
        
        self.reset_attempts[email] = now
        return True, 0


throttler = PasswordResetThrottler()

@app.route('/api/forgot_password_secure', methods=['POST'])
def forgot_password_secure():
    """
    SECURE: Rate limiting with cooling-off period
    
    Design: Prevents email bombing
    """
    data = request.get_json()
    email = data.get('email')
    
    # Check throttle
    can_reset, wait_time = throttler.can_request_reset(email)
    if not can_reset:
        return jsonify({
            'error': 'Too many reset requests',
            'retry_after': wait_time
        }), 429
    
    # Send reset email
    reset_token = secrets.token_urlsafe(32)
    # send_reset_email(email, reset_token)
    
    return jsonify({'message': 'Reset email sent'})


# Example 2: SECURE - Atomic Money Transfer
@app.route('/api/transfer_money_secure', methods=['POST'])
def transfer_money_secure():
    """
    SECURE: Use database transactions for atomicity
    
    Design: Prevents race conditions
    """
    data = request.get_json()
    from_account = data.get('from_account')
    to_account = data.get('to_account')
    amount = float(data.get('amount'))
    
    # Validate amount
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    
    conn = sqlite3.connect('bank.db')
    conn.isolation_level = 'EXCLUSIVE'  # Lock database
    
    try:
        cursor = conn.cursor()
        
        # Use FOR UPDATE to lock rows
        cursor.execute("""
            SELECT balance FROM accounts 
            WHERE id = ? 
            FOR UPDATE
        """, (from_account,))
        
        balance = cursor.fetchone()[0]
        
        if balance < amount:
            conn.rollback()
            return jsonify({'error': 'Insufficient funds'}), 400
        
        # Atomic update
        cursor.execute("""
            UPDATE accounts 
            SET balance = balance - ? 
            WHERE id = ? AND balance >= ?
        """, (amount, from_account, amount))
        
        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'error': 'Transfer failed'}), 400
        
        cursor.execute("""
            UPDATE accounts 
            SET balance = balance + ? 
            WHERE id = ?
        """, (amount, to_account))
        
        conn.commit()
        return jsonify({'message': 'Transfer successful'})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': 'Transaction failed'}), 500
    finally:
        conn.close()


# Example 3: SECURE - Purchase with Validation
@app.route('/api/purchase_secure', methods=['POST'])
def purchase_secure():
    """
    SECURE: Validate all business rules
    
    Design: Enforce constraints and limits
    """
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = int(data.get('quantity'))
    user_id = session.get('user_id')
    
    # Validate quantity
    if quantity <= 0:
        return jsonify({'error': 'Quantity must be positive'}), 400
    
    if quantity > 100:  # Maximum purchase limit
        return jsonify({'error': 'Exceeds maximum quantity'}), 400
    
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Get product details
    cursor.execute("SELECT price, stock FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    price, stock = product
    
    # Validate stock availability
    if stock < quantity:
        return jsonify({'error': 'Insufficient stock'}), 400
    
    total_price = price * quantity
    
    # Check user balance
    cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    balance = cursor.fetchone()[0]
    
    if balance < total_price:
        return jsonify({'error': 'Insufficient funds'}), 400
    
    # Atomic transaction
    try:
        # Update inventory
        cursor.execute("""
            UPDATE products 
            SET stock = stock - ? 
            WHERE id = ? AND stock >= ?
        """, (quantity, product_id, quantity))
        
        if cursor.rowcount == 0:
            return jsonify({'error': 'Purchase failed'}), 400
        
        # Charge user
        cursor.execute("""
            UPDATE users 
            SET balance = balance - ? 
            WHERE id = ? AND balance >= ?
        """, (total_price, user_id, total_price))
        
        conn.commit()
        return jsonify({'total': total_price, 'message': 'Purchase successful'})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': 'Transaction failed'}), 500


# Example 4: SECURE - Single-Use Coupon
@app.route('/api/apply_coupon_secure', methods=['POST'])
def apply_coupon_secure():
    """
    SECURE: Enforce single-use coupons
    
    Design: Track coupon usage per user/order
    """
    data = request.get_json()
    coupon_code = data.get('coupon_code')
    order_id = data.get('order_id')
    user_id = session.get('user_id')
    
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Check if coupon exists and is valid
    cursor.execute("""
        SELECT id, discount_percent, valid_until, max_uses, current_uses
        FROM coupons 
        WHERE code = ?
    """, (coupon_code,))
    
    coupon = cursor.fetchone()
    
    if not coupon:
        return jsonify({'error': 'Invalid coupon'}), 400
    
    coupon_id, discount, valid_until, max_uses, current_uses = coupon
    
    # Check expiration
    if valid_until and datetime.fromisoformat(valid_until) < datetime.now():
        return jsonify({'error': 'Coupon expired'}), 400
    
    # Check usage limit
    if max_uses and current_uses >= max_uses:
        return jsonify({'error': 'Coupon usage limit reached'}), 400
    
    # Check if already applied to this order
    cursor.execute("""
        SELECT id FROM coupon_usage 
        WHERE coupon_id = ? AND order_id = ?
    """, (coupon_id, order_id))
    
    if cursor.fetchone():
        return jsonify({'error': 'Coupon already applied'}), 400
    
    # Check if user already used this coupon
    cursor.execute("""
        SELECT id FROM coupon_usage 
        WHERE coupon_id = ? AND user_id = ?
    """, (coupon_id, user_id))
    
    if cursor.fetchone():
        return jsonify({'error': 'Coupon already used'}), 400
    
    # Apply discount
    try:
        cursor.execute("""
            UPDATE orders 
            SET total = total * (1 - ? / 100),
                coupon_applied = ?
            WHERE id = ? AND coupon_applied IS NULL
        """, (discount, coupon_code, order_id))
        
        if cursor.rowcount == 0:
            return jsonify({'error': 'Could not apply coupon'}), 400
        
        # Record usage
        cursor.execute("""
            INSERT INTO coupon_usage (coupon_id, order_id, user_id, used_at)
            VALUES (?, ?, ?, ?)
        """, (coupon_id, order_id, user_id, datetime.now()))
        
        # Update coupon usage count
        cursor.execute("""
            UPDATE coupons 
            SET current_uses = current_uses + 1 
            WHERE id = ?
        """, (coupon_id,))
        
        conn.commit()
        return jsonify({'message': f'{discount}% discount applied'})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': 'Failed to apply coupon'}), 500


# Example 5: SECURE - Constant-Time Login
import hashlib
import hmac

@app.route('/api/login_secure_timing', methods=['POST'])
def login_secure_timing():
    """
    SECURE: Constant-time response
    
    Design: Same response time regardless of username validity
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    # Always perform hash comparison (constant time)
    if user:
        stored_hash = user[0]
    else:
        # Dummy hash if user doesn't exist
        stored_hash = b'$2b$12$dummy.hash.for.constant.time.comparison'
    
    # Constant-time comparison using bcrypt
    import bcrypt
    is_valid = bcrypt.checkpw(password.encode(), stored_hash) and user is not None
    
    if is_valid:
        return jsonify({'message': 'Login successful'})
    else:
        # Generic error (same for invalid username or password)
        return jsonify({'error': 'Invalid credentials'}), 401


# ============================================================================
# DESIGN BEST PRACTICES
# ============================================================================

"""
SECURE DESIGN PRINCIPLES:

Threat Modeling:
✅ Identify assets and threats early
✅ Use STRIDE or PASTA methodology
✅ Document security requirements
✅ Review design with security team

Business Logic:
✅ Define all business rules explicitly
✅ Validate input ranges and limits
✅ Implement rate limiting
✅ Use atomic transactions
✅ Prevent race conditions

Security Requirements:
✅ Authentication requirements
✅ Authorization requirements
✅ Data validation rules
✅ Audit logging requirements
✅ Error handling strategy

Architecture:
✅ Defense in depth
✅ Least privilege
✅ Fail securely
✅ Separation of concerns
✅ Input validation layers

Testing:
✅ Security test cases
✅ Business logic abuse cases
✅ Race condition testing
✅ Load testing with security focus

DESIGN CHECKLIST:

✅ Threat model created
✅ Security requirements documented
✅ Business rules validated
✅ Race conditions prevented
✅ Rate limiting implemented
✅ Atomic operations used
✅ Input validation comprehensive
✅ Error handling consistent
✅ Audit logging complete
✅ Security review conducted
"""

if __name__ == '__main__':
    print("OWASP A04:2021 - Insecure Design Examples")
    print("=" * 60)
    print("\nThis file demonstrates:")
    print("- Business logic flaws")
    print("- Race conditions")
    print("- Missing input validation")
    print("- Coupon abuse")
    print("- Timing attacks")
    print("\nSecure designs include:")
    print("✅ Rate limiting and throttling")
    print("✅ Atomic transactions")
    print("✅ Comprehensive validation")
    print("✅ Single-use enforcement")
    print("✅ Constant-time operations")


