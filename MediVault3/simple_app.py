import os
import sqlite3
import hashlib
import secrets
import json
import qrcode
from datetime import datetime, timedelta
from io import BytesIO
import base64
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, send_file, redirect, url_for, session
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.config['SECRET_KEY'] = 'medivault-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Google OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

CORS(app)

# Initialize OAuth only if credentials are available
oauth = None
google = None
if app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET']:
    oauth = OAuth(app)
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('medivault.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        full_name TEXT NOT NULL,
        account_type TEXT DEFAULT 'patient',
        license_number TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )''')
    
    # Medical files table
    c.execute('''CREATE TABLE IF NOT EXISTS medical_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_type TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        description TEXT,
        category TEXT,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        doctor_name TEXT,
        hospital_name TEXT,
        blockchain_hash TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Emergency profiles table
    c.execute('''CREATE TABLE IF NOT EXISTS emergency_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        blood_type TEXT,
        allergies TEXT,
        medical_conditions TEXT,
        current_medications TEXT,
        emergency_contact_name TEXT,
        emergency_contact_phone TEXT,
        secondary_contact_name TEXT,
        secondary_contact_phone TEXT,
        primary_doctor_name TEXT,
        primary_doctor_phone TEXT,
        primary_doctor_hospital TEXT,
        organ_donor BOOLEAN DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Access logs table
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # QR codes table
    c.execute('''CREATE TABLE IF NOT EXISTS qr_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        qr_token TEXT UNIQUE NOT NULL,
        access_type TEXT DEFAULT 'emergency',
        expires_at TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    
    # Create sample data if users table is empty
    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        # Create sample patient
        patient_hash = generate_password_hash('password123')
        c.execute('''INSERT INTO users (email, password_hash, full_name, account_type) 
                     VALUES (?, ?, ?, ?)''', 
                  ('sakshi@example.com', patient_hash, 'Sakshi Verma', 'patient'))
        patient_id = c.lastrowid
        
        # Create sample doctor
        doctor_hash = generate_password_hash('doctor123')
        c.execute('''INSERT INTO users (email, password_hash, full_name, account_type, license_number) 
                     VALUES (?, ?, ?, ?, ?)''', 
                  ('dr.sharma@example.com', doctor_hash, 'Dr. Raj Sharma', 'doctor', 'MD123456'))
        
        # Create emergency profile for patient
        c.execute('''INSERT INTO emergency_profiles 
                     (user_id, blood_type, allergies, medical_conditions, current_medications,
                      emergency_contact_name, emergency_contact_phone, secondary_contact_name, 
                      secondary_contact_phone, primary_doctor_name, primary_doctor_phone, 
                      primary_doctor_hospital, organ_donor) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (patient_id, 'O+', 'Penicillin (Severe), Shellfish, Latex',
                   'Type 1 Diabetes (since age 12), Asthma',
                   'Insulin Glargine - 20 units daily, Albuterol Inhaler - as needed, Lisinopril - 10mg daily',
                   'Jay Gupta', '+91 90348 74362', 'Shreeya Singh', '+91 98704 35332',
                   'Dr. Moksh, MD', '+91 78983 76483', 'City General Hospital', 1))
        
        conn.commit()
    
    conn.close()

# Utility functions
def get_db_connection():
    conn = sqlite3.connect('medivault.db')
    conn.row_factory = sqlite3.Row
    return conn

def log_user_action(user_id, action, details=None):
    conn = get_db_connection()
    conn.execute('''INSERT INTO access_logs (user_id, action, details, ip_address) 
                    VALUES (?, ?, ?, ?)''',
                 (user_id, action, details, request.remote_addr))
    conn.commit()
    conn.close()

def store_on_chain(file_data):
    """Simulate blockchain storage"""
    file_hash = hashlib.sha256(file_data).hexdigest()
    return file_hash, {'status': 'confirmed', 'hash': file_hash, 'timestamp': datetime.now().isoformat()}

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_qr_code_image(data):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode()

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        required_fields = ['email', 'password', 'full_name', 'account_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        if data['account_type'] == 'doctor' and not data.get('license_number'):
            return jsonify({'error': 'License number is required for doctors'}), 400
        
        conn = get_db_connection()
        
        # Check if user exists
        existing = conn.execute('SELECT id FROM users WHERE email = ?', (data['email'],)).fetchone()
        if existing:
            conn.close()
            return jsonify({'error': 'User already exists'}), 400
        
        # Create user
        password_hash = generate_password_hash(data['password'])
        cursor = conn.execute('''INSERT INTO users (email, password_hash, full_name, account_type, license_number) 
                                VALUES (?, ?, ?, ?, ?)''',
                             (data['email'], password_hash, data['full_name'], 
                              data['account_type'], data.get('license_number')))
        user_id = cursor.lastrowid
        
        # Create emergency profile for patients
        if data['account_type'] == 'patient':
            conn.execute('INSERT INTO emergency_profiles (user_id) VALUES (?)', (user_id,))
        
        conn.commit()
        conn.close()
        
        log_user_action(user_id, 'registration', f'New {data["account_type"]} account')
        
        return jsonify({
            'message': 'Registration successful',
            'user_id': user_id,
            'account_type': data['account_type']
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND is_active = 1', 
                           (data['email'],)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], data['password']):
            log_user_action(user['id'], 'login', 'Successful login')
            
            return jsonify({
                'message': 'Login successful',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'full_name': user['full_name'],
                    'account_type': user['account_type']
                }
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Google OAuth routes
@app.route('/auth/google')
def google_login():
    try:
        if not google or not app.config['GOOGLE_CLIENT_ID']:
            return f'''
            <html>
            <head>
                <script>
                    window.opener.postMessage({{
                        type: 'google_auth_error',
                        error: 'Google OAuth is not configured. Please use email/password login.'
                    }}, window.location.origin);
                    window.close();
                </script>
            </head>
            <body>
                <p>Google OAuth not available. Please use email/password login.</p>
                <script>setTimeout(() => window.close(), 2000);</script>
            </body>
            </html>
            '''
            
        account_type = request.args.get('account_type', 'patient')
        session['account_type'] = account_type
        
        redirect_uri = url_for('google_callback', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        return f'''
        <html>
        <head>
            <script>
                window.opener.postMessage({{
                    type: 'google_auth_error',
                    error: 'Google OAuth temporarily unavailable. Please use email/password login.'
                }}, window.location.origin);
                window.close();
            </script>
        </head>
        <body>
            <p>Google login temporarily unavailable: {str(e)}</p>
            <script>setTimeout(() => window.close(), 2000);</script>
        </body>
        </html>
        '''

@app.route('/auth/google/callback')
def google_callback():
    try:
        if not google:
            return '<html><body><p>Google OAuth not configured</p></body></html>'
            
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            return '<html><body><p>Failed to get user information from Google</p></body></html>'
        
        email = user_info.get('email')
        full_name = user_info.get('name')
        account_type = session.get('account_type', 'patient')
        
        conn = get_db_connection()
        
        # Check if user exists
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            # User exists, log them in
            user_id = existing_user['id']
            log_user_action(user_id, 'google_login', 'Google OAuth login')
            
            user_data = {
                'id': existing_user['id'],
                'email': existing_user['email'],
                'full_name': existing_user['full_name'],
                'account_type': existing_user['account_type']
            }
        else:
            # Create new user
            cursor = conn.execute('''INSERT INTO users (email, full_name, account_type) 
                                    VALUES (?, ?, ?)''',
                                 (email, full_name, account_type))
            user_id = cursor.lastrowid
            
            # Create emergency profile for patients
            if account_type == 'patient':
                conn.execute('INSERT INTO emergency_profiles (user_id) VALUES (?)', (user_id,))
            
            conn.commit()
            log_user_action(user_id, 'google_registration', f'New {account_type} account via Google')
            
            user_data = {
                'id': user_id,
                'email': email,
                'full_name': full_name,
                'account_type': account_type
            }
        
        conn.close()
        
        # Return success response that frontend can handle
        dashboard_url = 'doctorsdashboard.html' if user_data['account_type'] == 'doctor' else 'dashboard.html'
        
        return f'''
        <html>
        <head>
            <script>
                // Store user data and redirect
                window.opener.postMessage({{
                    type: 'google_auth_success',
                    user: {user_data}
                }}, window.location.origin);
                window.close();
            </script>
        </head>
        <body>
            <p>Authentication successful. Redirecting...</p>
            <script>
                setTimeout(() => window.location.href = '/{dashboard_url}', 1000);
            </script>
        </body>
        </html>
        '''
        
    except Exception as e:
        return f'''
        <html>
        <head>
            <script>
                window.opener.postMessage({{
                    type: 'google_auth_error',
                    error: '{str(e)}'
                }}, window.location.origin);
                window.close();
            </script>
        </head>
        <body>
            <p>Authentication failed: {str(e)}</p>
        </body>
        </html>
        '''

# File management routes
@app.route('/api/files/upload', methods=['POST'])
def upload_file():
    try:
        user_id = request.form.get('user_id')
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '' or not file.filename:
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Read and process file
        file_data = file.read()
        file.seek(0)
        
        blockchain_hash, blockchain_record = store_on_chain(file_data)
        
        # Save file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        unique_filename = timestamp + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Save to database
        conn = get_db_connection()
        cursor = conn.execute('''INSERT INTO medical_files 
                                (user_id, filename, original_filename, file_path, file_type, file_size,
                                 description, category, doctor_name, hospital_name, blockchain_hash)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                             (user_id, unique_filename, filename, file_path, 
                              file.content_type or 'application/octet-stream', len(file_data),
                              request.form.get('description', ''), request.form.get('category', 'general'),
                              request.form.get('doctor_name', ''), request.form.get('hospital_name', ''),
                              blockchain_hash))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        log_user_action(user_id, 'file_upload', f'Uploaded: {filename}')
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'blockchain_record': blockchain_record
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<int:user_id>', methods=['GET'])
def get_files(user_id):
    try:
        conn = get_db_connection()
        files = conn.execute('''SELECT * FROM medical_files WHERE user_id = ? 
                               ORDER BY upload_date DESC''', (user_id,)).fetchall()
        conn.close()
        
        return jsonify({
            'files': [dict(file) for file in files]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    try:
        conn = get_db_connection()
        file_record = conn.execute('SELECT * FROM medical_files WHERE id = ?', 
                                 (file_id,)).fetchone()
        conn.close()
        
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        if os.path.exists(file_record['file_path']):
            return send_file(file_record['file_path'], 
                           as_attachment=True, 
                           download_name=file_record['original_filename'])
        else:
            return jsonify({'error': 'File not found on server'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Emergency profile routes
@app.route('/api/emergency-profile/<int:user_id>', methods=['GET', 'POST'])
def emergency_profile(user_id):
    try:
        conn = get_db_connection()
        
        if request.method == 'GET':
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            profile = conn.execute('SELECT * FROM emergency_profiles WHERE user_id = ?', 
                                 (user_id,)).fetchone()
            conn.close()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({
                'user': dict(user),
                'profile': dict(profile) if profile else {}
            }), 200
            
        elif request.method == 'POST':
            data = request.get_json()
            
            # Check if profile exists
            existing = conn.execute('SELECT id FROM emergency_profiles WHERE user_id = ?', 
                                  (user_id,)).fetchone()
            
            if existing:
                # Update existing profile
                conn.execute('''UPDATE emergency_profiles SET 
                               blood_type=?, allergies=?, medical_conditions=?, current_medications=?,
                               emergency_contact_name=?, emergency_contact_phone=?, 
                               secondary_contact_name=?, secondary_contact_phone=?,
                               primary_doctor_name=?, primary_doctor_phone=?, 
                               primary_doctor_hospital=?, organ_donor=?, updated_at=CURRENT_TIMESTAMP
                               WHERE user_id=?''',
                            (data.get('blood_type'), data.get('allergies'), 
                             data.get('medical_conditions'), data.get('current_medications'),
                             data.get('emergency_contact_name'), data.get('emergency_contact_phone'),
                             data.get('secondary_contact_name'), data.get('secondary_contact_phone'),
                             data.get('primary_doctor_name'), data.get('primary_doctor_phone'),
                             data.get('primary_doctor_hospital'), data.get('organ_donor', False),
                             user_id))
            else:
                # Create new profile
                conn.execute('''INSERT INTO emergency_profiles 
                               (user_id, blood_type, allergies, medical_conditions, current_medications,
                                emergency_contact_name, emergency_contact_phone, secondary_contact_name,
                                secondary_contact_phone, primary_doctor_name, primary_doctor_phone,
                                primary_doctor_hospital, organ_donor)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (user_id, data.get('blood_type'), data.get('allergies'),
                             data.get('medical_conditions'), data.get('current_medications'),
                             data.get('emergency_contact_name'), data.get('emergency_contact_phone'),
                             data.get('secondary_contact_name'), data.get('secondary_contact_phone'),
                             data.get('primary_doctor_name'), data.get('primary_doctor_phone'),
                             data.get('primary_doctor_hospital'), data.get('organ_donor', False)))
            
            conn.commit()
            conn.close()
            
            log_user_action(user_id, 'emergency_profile_update', 'Updated emergency profile')
            
            return jsonify({'message': 'Emergency profile updated successfully'}), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# QR code routes
@app.route('/api/qr/generate', methods=['POST'])
def generate_qr():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        access_type = data.get('access_type', 'emergency')
        
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400
        
        # Generate unique token
        qr_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=24)
        
        # Save QR record
        conn = get_db_connection()
        conn.execute('''INSERT INTO qr_codes (user_id, qr_token, access_type, expires_at)
                       VALUES (?, ?, ?, ?)''',
                    (user_id, qr_token, access_type, expires_at))
        conn.commit()
        conn.close()
        
        # Generate QR code
        qr_data = {
            'token': qr_token,
            'user_id': user_id,
            'access_type': access_type,
            'url': f'{request.host_url}api/qr/access/{qr_token}'
        }
        
        qr_image = generate_qr_code_image(json.dumps(qr_data))
        
        log_user_action(user_id, 'qr_generation', f'Generated {access_type} QR code')
        
        return jsonify({
            'message': 'QR code generated successfully',
            'qr_token': qr_token,
            'qr_image': f'data:image/png;base64,{qr_image}',
            'expires_at': expires_at.isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/qr/access/<token>')
def qr_access(token):
    try:
        conn = get_db_connection()
        qr_record = conn.execute('''SELECT * FROM qr_codes WHERE qr_token = ? 
                                   AND is_active = 1''', (token,)).fetchone()
        
        if not qr_record:
            conn.close()
            return jsonify({'error': 'Invalid QR code'}), 404
        
        # Check expiration
        if qr_record['expires_at'] and datetime.fromisoformat(qr_record['expires_at']) < datetime.now():
            conn.close()
            return jsonify({'error': 'QR code expired'}), 401
        
        # Get user and emergency profile
        user = conn.execute('SELECT * FROM users WHERE id = ?', 
                           (qr_record['user_id'],)).fetchone()
        emergency_profile = conn.execute('SELECT * FROM emergency_profiles WHERE user_id = ?',
                                       (qr_record['user_id'],)).fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        log_user_action(qr_record['user_id'], 'qr_access', f'QR accessed: {token}')
        
        return jsonify({
            'user': {
                'full_name': user['full_name'],
                'email': user['email']
            },
            'emergency_profile': dict(emergency_profile) if emergency_profile else {},
            'access_type': qr_record['access_type']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Dashboard stats
@app.route('/api/dashboard/stats/<int:user_id>')
def dashboard_stats(user_id):
    try:
        conn = get_db_connection()
        
        # Get file count
        file_count = conn.execute('SELECT COUNT(*) FROM medical_files WHERE user_id = ?', 
                                 (user_id,)).fetchone()[0]
        
        # Get recent activity
        logs = conn.execute('''SELECT action, details, timestamp FROM access_logs 
                              WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10''', 
                           (user_id,)).fetchall()
        
        conn.close()
        
        return jsonify({
            'total_files': file_count,
            'recent_activity': [dict(log) for log in logs]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    init_db()
    app.run(host='localhost', port=8000, debug=True)