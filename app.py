from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os
import subprocess
import pickle
import base64
import hashlib

app = Flask(__name__)

# Initialize database with sample data
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY, 
        username TEXT UNIQUE, 
        password TEXT, 
        email TEXT,
        role TEXT DEFAULT 'user'
    )''')
    
    # Products table
    cursor.execute('''CREATE TABLE products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        price REAL,
        description TEXT
    )''')
    
    # Insert sample data
    cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", 
                  ('admin', 'admin123', 'admin@demo.com', 'admin'))
    cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                  ('john', 'password', 'john@demo.com'))
    cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                  ('jane', 'secret', 'jane@demo.com'))
    
    cursor.execute("INSERT INTO products (name, price, description) VALUES (?, ?, ?)",
                  ('Laptop', 999.99, 'Gaming laptop'))
    cursor.execute("INSERT INTO products (name, price, description) VALUES (?, ?, ?)",
                  ('Phone', 599.99, 'Smartphone'))
    
    conn.commit()
    return conn

db_conn = init_db()

# Home page with API documentation
@app.route('/')
def home():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Aikido Security Demo - Vulnerable API</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; background: white; padding: 30px; border-radius: 8px; }
            .vulnerability { background: #ffebee; padding: 15px; margin: 10px 0; border-left: 4px solid #f44336; }
            .endpoint { background: #e3f2fd; padding: 15px; margin: 10px 0; border-left: 4px solid #2196f3; }
            code { background: #f5f5f5; padding: 2px 4px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Aikido Security Demo API</h1>
            <p>This is a <strong>deliberately vulnerable</strong> API designed to test Aikido Security's scanning capabilities.</p>
            
            <h2>🚨 Vulnerabilities Included:</h2>
            <div class="vulnerability">
                <strong>SQL Injection</strong> - Direct user input in database queries
            </div>
            <div class="vulnerability">
                <strong>Command Injection</strong> - Unsafe system command execution
            </div>
            <div class="vulnerability">
                <strong>Insecure Deserialization</strong> - Unsafe pickle deserialization
            </div>
            <div class="vulnerability">
                <strong>Server-Side Template Injection (SSTI)</strong> - Unsafe template rendering
            </div>
            <div class="vulnerability">
                <strong>Information Disclosure</strong> - Exposed sensitive data
            </div>
            
            <h2>📡 Available Endpoints:</h2>
            
            <div class="endpoint">
                <strong>GET /api/users</strong><br>
                Get users (SQL Injection vulnerable)<br>
                <code>?username=admin' OR '1'='1</code>
            </div>
            
            <div class="endpoint">
                <strong>POST /api/login</strong><br>
                Login endpoint (SQL Injection vulnerable)<br>
                <code>{"username": "admin' OR '1'='1", "password": "anything"}</code>
            </div>
            
            <div class="endpoint">
                <strong>GET /api/ping</strong><br>
                Ping utility (Command Injection vulnerable)<br>
                <code>?host=google.com; ls</code>
            </div>
            
            <div class="endpoint">
                <strong>POST /api/process</strong><br>
                Process data (Insecure Deserialization)<br>
                <code>{"data": "base64_encoded_pickle_data"}</code>
            </div>
            
            <div class="endpoint">
                <strong>GET /api/template</strong><br>
                Template rendering (SSTI vulnerable)<br>
                <code>?name={{7*7}}</code>
            </div>
            
            <div class="endpoint">
                <strong>GET /api/debug</strong><br>
                Debug information (Information Disclosure)<br>
                Exposes sensitive system information
            </div>
            
            <div class="endpoint">
                <strong>GET /health</strong><br>
                Health check endpoint
            </div>
            
            <h2>⚠️ Security Notice</h2>
            <p style="color: #d32f2f; font-weight: bold;">
                This API contains INTENTIONAL security vulnerabilities for testing purposes only. 
                Never use this code in production!
            </p>
        </div>
    </body>
    </html>
    """
    return html

# SQL Injection vulnerable endpoint
@app.route('/api/users', methods=['GET'])
def get_users():
    username = request.args.get('username', '')
    cursor = db_conn.cursor()
    
    # VULNERABILITY: SQL Injection - Direct string concatenation
    query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{username}%'"
    cursor.execute(query)
    users = cursor.fetchall()
    
    return jsonify({
        'users': [{'id': u[0], 'username': u[1], 'email': u[2], 'role': u[3]} for u in users],
        'query_used': query  # Exposing query for demonstration
    })

# SQL Injection in login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '')
    password = data.get('password', '')
    
    cursor = db_conn.cursor()
    
    # VULNERABILITY: SQL Injection in login
    query = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({
            'success': True,
            'user': {'id': user[0], 'username': user[1], 'role': user[2]},
            'token': 'fake_jwt_token_123'
        })
    else:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

# Command Injection vulnerable endpoint
@app.route('/api/ping', methods=['GET'])
def ping():
    host = request.args.get('host', 'localhost')
    
    # VULNERABILITY: Command Injection
    try:
        # Unsafe command execution
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
        return jsonify({
            'success': True,
            'result': result,
            'command': f"ping -c 1 {host}"
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'command': f"ping -c 1 {host}"
        }), 500

# Insecure Deserialization
@app.route('/api/process', methods=['POST'])
def process_data():
    data = request.get_json()
    if not data or 'data' not in data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        # VULNERABILITY: Insecure Deserialization
        encoded_data = data['data']
        decoded_data = base64.b64decode(encoded_data)
        processed_data = pickle.loads(decoded_data)  # Dangerous!
        
        return jsonify({
            'success': True,
            'processed': str(processed_data)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Server-Side Template Injection (SSTI)
@app.route('/api/template', methods=['GET'])
def template_render():
    name = request.args.get('name', 'World')
    
    # VULNERABILITY: Server-Side Template Injection
    template = f"Hello {name}!"
    try:
        # Unsafe template rendering
        result = render_template_string(template)
        return jsonify({
            'result': result,
            'template': template
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'template': template
        }), 500

# Information Disclosure
@app.route('/api/debug', methods=['GET'])
def debug_info():
    # VULNERABILITY: Information Disclosure
    return jsonify({
        'environment_variables': dict(os.environ),
        'current_directory': os.getcwd(),
        'python_path': os.sys.path,
        'database_query': "SELECT * FROM users",  # Exposing DB structure
        'secret_key': 'super_secret_key_123',
        'admin_credentials': {'username': 'admin', 'password': 'admin123'},
        'system_info': {
            'platform': os.name,
            'python_version': os.sys.version
        }
    })

# Products endpoint with more SQL injection
@app.route('/api/products', methods=['GET'])
def get_products():
    category = request.args.get('category', '')
    min_price = request.args.get('min_price', '0')
    
    cursor = db_conn.cursor()
    
    # VULNERABILITY: SQL Injection with numeric injection
    query = f"SELECT * FROM products WHERE price >= {min_price}"
    if category:
        query += f" AND description LIKE '%{category}%'"
    
    cursor.execute(query)
    products = cursor.fetchall()
    
    return jsonify({
        'products': [{'id': p[0], 'name': p[1], 'price': p[2], 'description': p[3]} for p in products],
        'query': query
    })

# File operation endpoint (Path Traversal potential)
@app.route('/api/files', methods=['GET'])
def read_file():
    filename = request.args.get('file', 'README.txt')
    
    # VULNERABILITY: Path Traversal
    try:
        # This is dangerous - no path validation
        with open(filename, 'r') as f:
            content = f.read()
        return jsonify({
            'filename': filename,
            'content': content
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'attempted_file': filename
        }), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': '2025-08-26',
        'vulnerabilities': 'intentionally_included'
    })

# CORS headers (overly permissive)
@app.after_request
def after_request(response):
    # VULNERABILITY: Overly permissive CORS
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Server'] = 'Vulnerable-Flask/1.0'
    return response

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    # VULNERABILITY: Debug mode enabled
    app.run(host='0.0.0.0', port=port, debug=True)
