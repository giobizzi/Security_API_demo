"""
API Security Demo - E-Commerce API with Vulnerabilities, Mitigations, and API Gateway
Demonstrates OWASP API Top 10 vulnerabilities with secure alternatives

Run with: python vulnerable_api_app.py
Access at: http://VM_IP:5000
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import jwt
import sqlite3
import hashlib
import datetime
import time
import json
import logging
from collections import defaultdict
from logging.handlers import RotatingFileHandler
import sys

app = Flask(__name__)
CORS(app)

# Configuration
SECRET_KEY = "secret_key_123"  # Intentionally weak for demo
TOKEN_EXPIRY_MINUTES = 60

# Rate limiting storage (in-memory for demo)
rate_limit_store = defaultdict(list)
RATE_LIMIT_MAX_REQUESTS = 5
RATE_LIMIT_WINDOW_SECONDS = 60

# ============================================================================
# LOGGING & SIEM INTEGRATION
# ============================================================================

# Configure structured logging for SIEM
class SIEMFormatter(logging.Formatter):
    """Custom formatter for SIEM-compatible logs (CEF format inspired)"""
    def format(self, record):
        log_data = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'severity': record.levelname,
            'event_type': getattr(record, 'event_type', 'general'),
            'message': record.getMessage(),
            'source_ip': getattr(record, 'source_ip', None),
            'user_id': getattr(record, 'user_id', None),
            'username': getattr(record, 'username', None),
            'endpoint': getattr(record, 'endpoint', None),
            'method': getattr(record, 'method', None),
            'status_code': getattr(record, 'status_code', None),
            'attack_type': getattr(record, 'attack_type', None),
            'blocked': getattr(record, 'blocked', None),
            'details': getattr(record, 'details', {})
        }
        return json.dumps(log_data)

# Setup multiple log handlers
def setup_logging():
    """Configure logging for security events and SIEM integration"""
    
    # Security events logger (for SIEM)
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    
    # File handler for security events (SIEM can tail this)
    security_handler = RotatingFileHandler(
        'security_events.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    security_handler.setFormatter(SIEMFormatter())
    security_logger.addHandler(security_handler)
    
    # Console handler for demo visibility
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        '🔒 [%(levelname)s] %(message)s'
    ))
    security_logger.addHandler(console_handler)
    
    # Application logger
    app_logger = logging.getLogger('app')
    app_logger.setLevel(logging.INFO)
    app_handler = logging.StreamHandler(sys.stdout)
    app_handler.setFormatter(logging.Formatter(
        '📋 [%(asctime)s] %(message)s'
    ))
    app_logger.addHandler(app_handler)
    
    return security_logger, app_logger

security_log, app_log = setup_logging()

def log_security_event(event_type, attack_type=None, blocked=False, **kwargs):
    """
    Log security events in SIEM-compatible format
    
    Args:
        event_type: Type of event (auth_attempt, api_access, attack_detected, etc.)
        attack_type: Type of attack if applicable (bola, mass_assignment, brute_force, etc.)
        blocked: Whether the attack was blocked
        **kwargs: Additional context (user_id, endpoint, details, etc.)
    """
    extra = {
        'event_type': event_type,
        'attack_type': attack_type,
        'blocked': blocked,
        'source_ip': request.remote_addr if request else None,
        'endpoint': request.path if request else None,
        'method': request.method if request else None,
        'user_id': kwargs.get('user_id'),
        'username': kwargs.get('username'),
        'status_code': kwargs.get('status_code'),
        'details': kwargs.get('details', {})
    }
    
    level = logging.WARNING if attack_type and not blocked else logging.INFO
    security_log.log(level, kwargs.get('message', f'{event_type} event'), extra=extra)

# Database setup
def init_db():
    """Initialize SQLite database with sample data"""
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            credit_card TEXT,
            ssn TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    app_log.info("Database initialized successfully")

def get_db():
    """Get database connection"""
    conn = sqlite3.connect('ecommerce.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database on startup
init_db()

# ============================================================================
# AUTHENTICATION HELPERS
# ============================================================================

def hash_password(password):
    """Simple password hashing (intentionally weak for demo)"""
    return hashlib.md5(password.encode()).hexdigest()

def generate_token(user_id, username, role):
    """Generate JWT token"""
    secret =  SECRET_KEY
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRY_MINUTES)
    }
    return jwt.encode(payload, secret, algorithm='HS256')

def token_required():
    """Decorator for endpoints requiring authentication"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            
            if not token:
                log_security_event(
                    'auth_failed',
                    message='Missing authentication token',
                    status_code=401
                )
                return jsonify({'error': 'Token is missing'}), 401
            
            if token.startswith('Bearer '):
                token = token[7:]
            
            try:
                secret = SECRET_KEY
                data = jwt.decode(token, secret, algorithms=['HS256'])
                request.user = data
                
                log_security_event(
                    'auth_success',
                    user_id=data.get('user_id'),
                    username=data.get('username'),
                    message=f"User {data.get('username')} authenticated"
                )
            except jwt.ExpiredSignatureError:
                log_security_event(
                    'auth_failed',
                    message='Token expired',
                    status_code=401
                )
                return jsonify({'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError:
                log_security_event(
                    'auth_failed',
                    message='Invalid token',
                    status_code=401
                )
                return jsonify({'error': 'Invalid token'}), 401
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def rate_limit(max_requests=RATE_LIMIT_MAX_REQUESTS, window=RATE_LIMIT_WINDOW_SECONDS):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            # Clean old requests
            rate_limit_store[client_ip] = [
                req_time for req_time in rate_limit_store[client_ip]
                if current_time - req_time < window
            ]
            
            # Check rate limit
            if len(rate_limit_store[client_ip]) >= max_requests:
                log_security_event(
                    'rate_limit_exceeded',
                    attack_type='brute_force',
                    blocked=True,
                    message=f'Rate limit exceeded from {client_ip}',
                    details={'requests': len(rate_limit_store[client_ip]), 'window': window}
                )
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': window
                }), 429
            
            # Add current request
            rate_limit_store[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data.get('username')
    password = data.get('password')
    email = data.get('email', f'{username}@example.com')
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # VULNERABILITY: Weak password hashing (MD5)
        hashed_pw = hash_password(password)
        
        cursor.execute(
            'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
            (username, email, hashed_pw, 'user')
        )
        conn.commit()
        user_id = cursor.lastrowid
        
        # Create sample order for the user
        cursor.execute(
            'INSERT INTO orders (user_id, product_name, amount) VALUES (?, ?, ?)',
            (user_id, 'Sample Product', 99.99)
        )
        conn.commit()
        
        token = generate_token(user_id, username, 'user')
        
        log_security_event(
            'user_registered',
            user_id=user_id,
            username=username,
            message=f'New user registered: {username}',
            status_code=201
        )
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'username': username,
            'token': token
        }), 201
        
    except sqlite3.IntegrityError:
        log_security_event(
            'registration_failed',
            message=f'Duplicate username: {username}',
            status_code=409
        )
        return jsonify({'error': 'Username already exists'}), 409
    finally:
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    VULNERABLE: No rate limiting on login attempts
    Allows brute force attacks
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data.get('username')
    password = hash_password(data.get('password'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT id, username, role FROM users WHERE username = ? AND password = ?',
        (username, password)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        token = generate_token(user['id'], user['username'], user['role'])
        
        log_security_event(
            'login_success',
            user_id=user['id'],
            username=user['username'],
            message=f'Successful login: {username}',
            status_code=200
        )
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            }
        })
    
    log_security_event(
        'login_failed',
        attack_type='brute_force',
        blocked=False,
        message=f'Failed login attempt for: {username}',
        details={'username': username},
        status_code=401
    )
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/login-secure', methods=['POST'])
@rate_limit(max_requests=3, window=60)
def login_secure():
    """
    SECURE: Rate limited login endpoint
    Prevents brute force attacks
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data.get('username')
    password = hash_password(data.get('password'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT id, username, role FROM users WHERE username = ? AND password = ?',
        (username, password)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        token = generate_token(user['id'], user['username'], user['role'])
        
        log_security_event(
            'login_success',
            user_id=user['id'],
            username=user['username'],
            message=f'Secure login successful: {username}',
            status_code=200
        )
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            }
        })
    
    log_security_event(
        'login_failed',
        attack_type='brute_force',
        blocked=True,
        message=f'Failed secure login attempt for: {username}',
        details={'username': username, 'rate_limited': True},
        status_code=401
    )
    
    return jsonify({'error': 'Invalid credentials'}), 401

# ============================================================================
# VULNERABLE USER ENDPOINTS (OWASP API3 - Excessive Data Exposure)
# ============================================================================

@app.route('/api/users/<int:user_id>', methods=['GET'])
@token_required()
def get_user(user_id):
    """
    VULNERABLE: API3 - Excessive Data Exposure
    Returns ALL user data including sensitive PII (credit card, SSN)
    """
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Log excessive data exposure
    log_security_event(
        'data_exposure',
        attack_type='excessive_data_exposure',
        blocked=False,
        user_id=request.user.get('user_id'),
        username=request.user.get('username'),
        message=f'User {request.user.get("username")} accessed full user profile {user_id}',
        details={'exposed_fields': ['password', 'credit_card', 'ssn'], 'target_user_id': user_id},
        status_code=200
    )
    
    # VULNERABILITY: Returns ALL fields including sensitive data
    return jsonify(dict(user))

@app.route('/api/users/<int:user_id>/secure', methods=['GET'])
@token_required()
def get_user_secure(user_id):
    """
    SECURE: Only returns necessary user data
    Filters out sensitive PII
    """
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # MITIGATION: Only return necessary fields
    safe_user = {
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        'created_at': user['created_at']
    }
    
    log_security_event(
        'api_access',
        user_id=request.user.get('user_id'),
        username=request.user.get('username'),
        message=f'Secure user profile access: {user_id}',
        details={'filtered_fields': ['password', 'credit_card', 'ssn']},
        status_code=200
    )
    
    return jsonify(safe_user)

# ============================================================================
# VULNERABLE UPDATE ENDPOINT (OWASP API6 - Mass Assignment)
# ============================================================================

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required()
def update_user(user_id):
    """
    VULNERABLE: API6 - Mass Assignment
    Allows updating ANY field including 'role' (privilege escalation)
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # VULNERABILITY: No field validation - can update ANY field
    update_fields = []
    values = []
    
    for key, value in data.items():
        if key != 'id':  # Don't allow ID updates
            update_fields.append(f'{key} = ?')
            values.append(value)
    
    if not update_fields:
        return jsonify({'error': 'No valid fields to update'}), 400
    
    values.append(user_id)
    query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
    
    cursor.execute(query, values)
    conn.commit()
    conn.close()
    
    # Log potential privilege escalation
    if 'role' in data:
        log_security_event(
            'privilege_escalation',
            attack_type='mass_assignment',
            blocked=False,
            user_id=request.user.get('user_id'),
            username=request.user.get('username'),
            message=f'PRIVILEGE ESCALATION: User {request.user.get("username")} updated role field',
            details={'updated_fields': list(data.keys()), 'new_role': data.get('role'), 'target_user_id': user_id},
            status_code=200
        )
    else:
        log_security_event(
            'api_access',
            user_id=request.user.get('user_id'),
            username=request.user.get('username'),
            message=f'User update: {user_id}',
            details={'updated_fields': list(data.keys())},
            status_code=200
        )
    
    return jsonify({
        'message': 'User updated successfully',
        'updated_fields': list(data.keys())
    })

@app.route('/api/users/<int:user_id>/secure', methods=['PUT'])
@token_required()
def update_user_secure(user_id):
    """
    SECURE: Only allows updating whitelisted fields
    Prevents privilege escalation
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # MITIGATION: Whitelist of allowed fields
    ALLOWED_FIELDS = {'email', 'username'}
    
    # Check authorization - users can only update their own profile
    if request.user['user_id'] != user_id and request.user['role'] != 'admin':
        log_security_event(
            'authorization_failed',
            attack_type='bola',
            blocked=True,
            user_id=request.user.get('user_id'),
            username=request.user.get('username'),
            message=f'Unauthorized update attempt by {request.user.get("username")} on user {user_id}',
            details={'target_user_id': user_id},
            status_code=403
        )
        return jsonify({'error': 'Unauthorized - can only update your own profile'}), 403
    
    # Check for suspicious fields
    suspicious_fields = [k for k in data.keys() if k not in ALLOWED_FIELDS]
    if suspicious_fields:
        log_security_event(
            'mass_assignment_blocked',
            attack_type='mass_assignment',
            blocked=True,
            user_id=request.user.get('user_id'),
            username=request.user.get('username'),
            message=f'Mass assignment attempt blocked: suspicious fields detected',
            details={'suspicious_fields': suspicious_fields, 'target_user_id': user_id},
            status_code=200
        )
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Only update whitelisted fields
    update_fields = []
    values = []
    
    for key, value in data.items():
        if key in ALLOWED_FIELDS:
            update_fields.append(f'{key} = ?')
            values.append(value)
    
    if not update_fields:
        return jsonify({'error': 'No valid fields to update'}), 400
    
    values.append(user_id)
    query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
    
    cursor.execute(query, values)
    conn.commit()
    conn.close()
    
    log_security_event(
        'api_access',
        user_id=request.user.get('user_id'),
        username=request.user.get('username'),
        message=f'Secure user update: {user_id}',
        details={'updated_fields': [k for k in data.keys() if k in ALLOWED_FIELDS]},
        status_code=200
    )
    
    return jsonify({
        'message': 'User updated successfully',
        'updated_fields': [k for k in data.keys() if k in ALLOWED_FIELDS]
    })

# ============================================================================
# VULNERABLE ORDER ENDPOINTS (OWASP API1 - BOLA)
# ============================================================================

@app.route('/api/orders/<int:order_id>', methods=['GET'])
@token_required()
def get_order(order_id):
    """
    VULNERABLE: API1 - Broken Object Level Authorization (BOLA)
    Does NOT verify if the authenticated user owns this order
    Any user can access any order by changing the order_id
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # VULNERABILITY: No authorization check
    cursor.execute('''
        SELECT o.*, u.username, u.email 
        FROM orders o 
        JOIN users u ON o.user_id = u.id 
        WHERE o.id = ?
    ''', (order_id,))
    
    order = cursor.fetchone()
    conn.close()
    
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    # Log BOLA vulnerability
    if order['user_id'] != request.user.get('user_id'):
        log_security_event(
            'bola_attack',
            attack_type='bola',
            blocked=False,
            user_id=request.user.get('user_id'),
            username=request.user.get('username'),
            message=f'BOLA ATTACK: User {request.user.get("username")} accessed order {order_id} belonging to user {order["user_id"]}',
            details={'order_id': order_id, 'order_owner_id': order['user_id'], 'attacker_id': request.user.get('user_id')},
            status_code=200
        )
    
    return jsonify(dict(order))

@app.route('/api/secure/orders/<int:order_id>', methods=['GET'])
@token_required()
def get_order_secure(order_id):
    """
    SECURE: Proper authorization check
    Verifies the authenticated user owns the order before returning it
    """
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT o.*, u.username, u.email 
        FROM orders o 
        JOIN users u ON o.user_id = u.id 
        WHERE o.id = ?
    ''', (order_id,))
    
    order = cursor.fetchone()
    conn.close()
    
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    # MITIGATION: Check if user owns this order
    if order['user_id'] != request.user['user_id']:
        log_security_event(
            'bola_blocked',
            attack_type='bola',
            blocked=True,
            user_id=request.user.get('user_id'),
            username=request.user.get('username'),
            message=f'BOLA BLOCKED: User {request.user.get("username")} attempted to access order {order_id}',
            details={'order_id': order_id, 'order_owner_id': order['user_id']},
            status_code=403
        )
        return jsonify({'error': 'Unauthorized - this order belongs to another user'}), 403
    
    log_security_event(
        'api_access',
        user_id=request.user.get('user_id'),
        username=request.user.get('username'),
        message=f'Authorized order access: {order_id}',
        status_code=200
    )
    
    return jsonify(dict(order))

@app.route('/api/orders', methods=['GET'])
@token_required()
def list_orders():
    """
    VULNERABLE: Returns ALL orders without filtering
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # VULNERABILITY: No filtering by user
    cursor.execute('SELECT * FROM orders')
    orders = cursor.fetchall()
    conn.close()
    
    log_security_event(
        'data_exposure',
        attack_type='excessive_data_exposure',
        blocked=False,
        user_id=request.user.get('user_id'),
        username=request.user.get('username'),
        message=f'User {request.user.get("username")} accessed ALL orders',
        details={'total_orders': len(orders)},
        status_code=200
    )
    
    return jsonify([dict(order) for order in orders])

@app.route('/api/secure/orders', methods=['GET'])
@token_required()
def list_orders_secure():
    """
    SECURE: Only returns orders belonging to the authenticated user
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # MITIGATION: Filter by authenticated user
    cursor.execute('SELECT * FROM orders WHERE user_id = ?', (request.user['user_id'],))
    orders = cursor.fetchall()
    conn.close()
    
    log_security_event(
        'api_access',
        user_id=request.user.get('user_id'),
        username=request.user.get('username'),
        message=f'User accessed own orders',
        details={'order_count': len(orders)},
        status_code=200
    )
    
    return jsonify([dict(order) for order in orders])

# ============================================================================
# SIEM INTEGRATION ENDPOINTS
# ============================================================================

@app.route('/api/siem/events', methods=['GET'])
def get_security_events():
    """
    Endpoint to retrieve recent security events for SIEM
    In production, SIEM would tail the log file or use syslog
    """
    try:
        with open('security_events.log', 'r') as f:
            lines = f.readlines()
            # Return last 100 events
            recent_events = [json.loads(line) for line in lines[-100:]]
            return jsonify({
                'total': len(recent_events),
                'events': recent_events
            })
    except FileNotFoundError:
        return jsonify({'total': 0, 'events': []})

@app.route('/api/siem/stats', methods=['GET'])
def get_security_stats():
    """Get security statistics for dashboards"""
    try:
        with open('security_events.log', 'r') as f:
            events = [json.loads(line) for line in f.readlines()]
            
        stats = {
            'total_events': len(events),
            'by_type': {},
            'by_attack_type': {},
            'blocked_attacks': 0,
            'unblocked_attacks': 0
        }
        
        for event in events:
            # Count by event type
            event_type = event.get('event_type', 'unknown')
            stats['by_type'][event_type] = stats['by_type'].get(event_type, 0) + 1
            
            # Count by attack type
            attack_type = event.get('attack_type')
            if attack_type:
                stats['by_attack_type'][attack_type] = stats['by_attack_type'].get(attack_type, 0) + 1
                
                if event.get('blocked'):
                    stats['blocked_attacks'] += 1
                else:
                    stats['unblocked_attacks'] += 1
        
        return jsonify(stats)
    except FileNotFoundError:
        return jsonify({
            'total_events': 0,
            'by_type': {},
            'by_attack_type': {},
            'blocked_attacks': 0,
            'unblocked_attacks': 0
        })

# ============================================================================
# DOCUMENTATION & HEALTH ENDPOINTS
# ============================================================================

@app.route('/')
def index():
    """API documentation"""
    return jsonify({
        'api': 'E-Commerce API Security Demo with SIEM Integration',
        'version': '2.0',
        'endpoints': {
            'authentication': {
                'POST /api/auth/register': 'Register new user',
                'POST /api/auth/login': 'Login (vulnerable - no rate limit)',
                'POST /api/auth/login-secure': 'Login (secure - rate limited)'
            },
            'users_vulnerable': {
                'GET /api/users/:id': 'Get user (exposes ALL data)',
                'PUT /api/users/:id': 'Update user (mass assignment vulnerability)'
            },
            'users_secure': {
                'GET /api/users/:id/secure': 'Get user (filtered data)',
                'PUT /api/users/:id/secure': 'Update user (whitelisted fields only)'
            },
            'orders_vulnerable': {
                'GET /api/orders/:id': 'Get order (BOLA vulnerability)',
                'GET /api/orders': 'List all orders (no filtering)'
            },
            'orders_secure': {
                'GET /api/secure/orders/:id': 'Get order (with authorization)',
                'GET /api/secure/orders': 'List user orders (filtered)'
            },
            'siem_integration': {
                'GET /api/siem/events': 'Recent security events (last 100)',
                'GET /api/siem/stats': 'Security statistics dashboard'
            }
        },
        'vulnerabilities_demonstrated': [
            'API1: Broken Object Level Authorization (BOLA)',
            'API2: Broken Authentication (no rate limiting)',
            'API3: Excessive Data Exposure',
            'API6: Mass Assignment'
        ],
        'security_features': {
            'logging': 'Structured JSON logs in security_events.log',
            'siem_compatible': 'CEF-inspired format for Splunk, ELK, etc.',
            'rate_limiting': 'Implemented on secure endpoints',
            'authorization': 'BOLA protection on secure endpoints'
        }
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.datetime.utcnow().isoformat()})

# ============================================================================
# RUN APPLICATION
# ============================================================================

if __name__ == '__main__':
    print("=" * 80)
    print("API Security Demo Server Starting...")
    print("=" * 80)
    print("\n🔓 VULNERABLE endpoints demonstrate OWASP API Top 10 issues")
    print("🔒 SECURE endpoints show proper mitigations")
    print("📊 SIEM logging enabled - check security_events.log")
    print("Access documentation at: http://localhost:5000/")
    print("Security events: http://localhost:5000/api/siem/events")
    print("Security stats: http://localhost:5000/api/siem/stats")
    print("=" * 80)
    
    app.run(debug=True, host='0.0.0.0', port=5000)