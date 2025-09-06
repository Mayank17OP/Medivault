import os
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import qrcode
from io import BytesIO
import base64
from PIL import Image
import json

from flask import Flask, request, jsonify, send_file, url_for, session, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from authlib.integrations.flask_client import OAuth

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'medivault-super-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///medivault.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-string')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Google OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
login_manager = LoginManager()
login_manager.init_app(app)
cors = CORS(app)
oauth = OAuth(app)

# Configure Google OAuth
google = None
if app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET']:
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    full_name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(20), nullable=False, default='patient')
    license_number = db.Column(db.String(50))
    google_id = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)
    
    # Relationships
    medical_files = db.relationship('MedicalFile', backref='owner', lazy=True)
    access_logs = db.relationship('AccessLog', backref='user', lazy=True)
    emergency_profile = db.relationship('EmergencyProfile', backref='user', uselist=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_active(self):
        return self.active
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'full_name': self.full_name,
            'account_type': self.account_type,
            'license_number': self.license_number,
            'created_at': self.created_at.isoformat(),
            'is_active': self.active
        }

class MedicalFile(db.Model):
    __tablename__ = 'medical_files'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    doctor_name = db.Column(db.String(100))
    hospital_name = db.Column(db.String(100))
    blockchain_hash = db.Column(db.String(64))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    access_permissions = db.relationship('FileAccessPermission', backref='file', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'description': self.description,
            'category': self.category,
            'upload_date': self.upload_date.isoformat(),
            'doctor_name': self.doctor_name,
            'hospital_name': self.hospital_name,
            'blockchain_hash': self.blockchain_hash
        }

class FileAccessPermission(db.Model):
    __tablename__ = 'file_access_permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('medical_files.id'), nullable=False)
    granted_to_email = db.Column(db.String(120), nullable=False)
    granted_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    permission_type = db.Column(db.String(20), default='view')
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat()
        }

class EmergencyProfile(db.Model):
    __tablename__ = 'emergency_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    blood_type = db.Column(db.String(5))
    allergies = db.Column(db.Text)
    medical_conditions = db.Column(db.Text)
    current_medications = db.Column(db.Text)
    emergency_contact_name = db.Column(db.String(100))
    emergency_contact_phone = db.Column(db.String(20))
    secondary_contact_name = db.Column(db.String(100))
    secondary_contact_phone = db.Column(db.String(20))
    primary_doctor_name = db.Column(db.String(100))
    primary_doctor_phone = db.Column(db.String(20))
    primary_doctor_hospital = db.Column(db.String(100))
    organ_donor = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'blood_type': self.blood_type,
            'allergies': self.allergies,
            'medical_conditions': self.medical_conditions,
            'current_medications': self.current_medications,
            'emergency_contact_name': self.emergency_contact_name,
            'emergency_contact_phone': self.emergency_contact_phone,
            'secondary_contact_name': self.secondary_contact_name,
            'secondary_contact_phone': self.secondary_contact_phone,
            'primary_doctor_name': self.primary_doctor_name,
            'primary_doctor_phone': self.primary_doctor_phone,
            'primary_doctor_hospital': self.primary_doctor_hospital,
            'organ_donor': self.organ_donor,
            'updated_at': self.updated_at.isoformat()
        }

class QRCodeRecord(db.Model):
    __tablename__ = 'qr_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    qr_token = db.Column(db.String(64), unique=True, nullable=False)
    access_type = db.Column(db.String(20), default='emergency')
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Blockchain Simulation Functions
def store_on_chain(file_data):
    """Simulate storing file hash on blockchain"""
    file_hash = hashlib.sha256(file_data).hexdigest()
    transaction_id = secrets.token_hex(32)
    
    blockchain_record = {
        'transaction_id': transaction_id,
        'file_hash': file_hash,
        'timestamp': datetime.utcnow().isoformat(),
        'block_number': secrets.randbelow(1000000),
        'status': 'confirmed'
    }
    
    return file_hash, blockchain_record

def verify_hash(file_data, stored_hash):
    """Verify file integrity against blockchain hash"""
    current_hash = hashlib.sha256(file_data).hexdigest()
    return current_hash == stored_hash

# Utility Functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'dicom'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_user_action(user_id, action, details=None):
    """Log user actions for audit trail"""
    log_entry = AccessLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(log_entry)
    db.session.commit()

def generate_qr_code(data, size=(200, 200)):
    """Generate QR code image"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img = img.resize(size, Image.Resampling.LANCZOS)
    
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return img_base64

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        required_fields = ['email', 'password', 'full_name', 'account_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return jsonify({'error': 'User with this email already exists'}), 400
        
        if data['account_type'] not in ['patient', 'doctor']:
            return jsonify({'error': 'Invalid account type'}), 400
        
        if data['account_type'] == 'doctor' and not data.get('license_number'):
            return jsonify({'error': 'License number is required for doctors'}), 400
        
        user = User(
            email=data['email'],
            full_name=data['full_name'],
            account_type=data['account_type'],
            license_number=data.get('license_number')
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        if user.account_type == 'patient':
            emergency_profile = EmergencyProfile(user_id=user.id)
            db.session.add(emergency_profile)
            db.session.commit()
        
        log_user_action(user.id, 'user_registration', f'New {user.account_type} account created')
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'access_token': access_token
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if user and user.check_password(data['password']) and user.is_active():
            login_user(user)
            log_user_action(user.id, 'login', 'Successful email/password login')
            access_token = create_access_token(identity=user.id)
            
            return jsonify({
                'message': 'Login successful',
                'user': user.to_dict(),
                'access_token': access_token
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/auth/google/login')
def google_login():
    if not google:
        return jsonify({'error': 'Google OAuth not configured'}), 400
    
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/api/auth/google/callback')
def google_callback():
    try:
        if not google:
            return jsonify({'error': 'Google OAuth not configured'}), 400
            
        token = google.authorize_access_token()
        user_info = token['userinfo']
        
        user = User.query.filter_by(google_id=user_info['sub']).first()
        
        if not user:
            user = User.query.filter_by(email=user_info['email']).first()
            if user:
                user.google_id = user_info['sub']
            else:
                user = User(
                    email=user_info['email'],
                    full_name=user_info['name'],
                    google_id=user_info['sub'],
                    account_type='patient'
                )
                db.session.add(user)
                db.session.flush()
                
                emergency_profile = EmergencyProfile(user_id=user.id)
                db.session.add(emergency_profile)
        
        db.session.commit()
        login_user(user)
        log_user_action(user.id, 'login', 'Successful Google OAuth login')
        access_token = create_access_token(identity=user.id)
        
        dashboard_url = '/dashboard.html' if user.account_type == 'patient' else '/doctorsdashboard.html'
        return redirect(f'{dashboard_url}?token={access_token}')
        
    except Exception as e:
        return jsonify({'error': f'Google login failed: {str(e)}'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'user': user.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get profile: {str(e)}'}), 500

# File Management Routes
@app.route('/api/files/upload', methods=['POST'])
@jwt_required()
def upload_file():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '' or file.filename is None:
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        file_data = file.read()
        file.seek(0)
        
        blockchain_hash, blockchain_record = store_on_chain(file_data)
        
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        unique_filename = timestamp + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        medical_file = MedicalFile(
            filename=unique_filename,
            original_filename=filename,
            file_path=file_path,
            file_type=file.content_type or 'application/octet-stream',
            file_size=len(file_data),
            description=request.form.get('description', ''),
            category=request.form.get('category', 'general'),
            doctor_name=request.form.get('doctor_name', ''),
            hospital_name=request.form.get('hospital_name', ''),
            blockchain_hash=blockchain_hash,
            user_id=user_id
        )
        
        db.session.add(medical_file)
        db.session.commit()
        
        log_user_action(user_id, 'file_upload', f'Uploaded file: {filename}')
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file': medical_file.to_dict(),
            'blockchain_record': blockchain_record
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'File upload failed: {str(e)}'}), 500

@app.route('/api/files', methods=['GET'])
@jwt_required()
def get_files():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        category = request.args.get('category')
        limit = request.args.get('limit', type=int)
        
        query = MedicalFile.query.filter_by(user_id=user_id)
        
        if category:
            query = query.filter_by(category=category)
        
        query = query.order_by(MedicalFile.upload_date.desc())
        
        if limit:
            query = query.limit(limit)
        
        files = query.all()
        
        return jsonify({
            'files': [file.to_dict() for file in files]
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get files: {str(e)}'}), 500

@app.route('/api/files/<int:file_id>/download', methods=['GET'])
@jwt_required()
def download_file(file_id):
    try:
        user_id = get_jwt_identity()
        file_record = MedicalFile.query.get(file_id)
        
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        if file_record.user_id != user_id:
            current_user_obj = User.query.get(user_id)
            if current_user_obj:
                permission = FileAccessPermission.query.filter_by(
                    file_id=file_id,
                    granted_to_email=current_user_obj.email,
                    is_active=True
                ).first()
                
                if not permission or (permission.expires_at and permission.expires_at < datetime.utcnow()):
                    return jsonify({'error': 'Access denied'}), 403
        
        if os.path.exists(file_record.file_path):
            with open(file_record.file_path, 'rb') as f:
                file_data = f.read()
            
            if not verify_hash(file_data, file_record.blockchain_hash):
                return jsonify({'error': 'File integrity check failed'}), 400
            
            log_user_action(user_id, 'file_download', f'Downloaded file: {file_record.original_filename}')
            
            return send_file(
                file_record.file_path,
                as_attachment=True,
                download_name=file_record.original_filename
            )
        else:
            return jsonify({'error': 'File not found on server'}), 404
            
    except Exception as e:
        return jsonify({'error': f'File download failed: {str(e)}'}), 500

@app.route('/api/files/<int:file_id>/share', methods=['POST'])
@jwt_required()
def share_file(file_id):
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        file_record = MedicalFile.query.get(file_id)
        if not file_record or file_record.user_id != user_id:
            return jsonify({'error': 'File not found'}), 404
        
        if not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400
        
        expires_at = None
        if data.get('expires_hours'):
            expires_at = datetime.utcnow() + timedelta(hours=data['expires_hours'])
        
        permission = FileAccessPermission(
            file_id=file_id,
            granted_to_email=data['email'],
            granted_by_user_id=user_id,
            permission_type=data.get('permission_type', 'view'),
            expires_at=expires_at
        )
        
        db.session.add(permission)
        db.session.commit()
        
        log_user_action(user_id, 'file_share', f'Shared file {file_record.original_filename} with {data["email"]}')
        
        access_link = url_for('download_file', file_id=file_id, _external=True)
        
        return jsonify({
            'message': 'File shared successfully',
            'access_link': access_link,
            'expires_at': expires_at.isoformat() if expires_at else None
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'File sharing failed: {str(e)}'}), 500

# Emergency Profile Routes
@app.route('/api/emergency-profile', methods=['GET', 'POST'])
@jwt_required()
def emergency_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if request.method == 'GET':
            profile = EmergencyProfile.query.filter_by(user_id=user_id).first()
            if not profile:
                profile = EmergencyProfile(user_id=user_id)
                db.session.add(profile)
                db.session.commit()
            
            return jsonify({
                'user': user.to_dict(),
                'profile': profile.to_dict()
            }), 200
        
        elif request.method == 'POST':
            data = request.get_json()
            
            profile = EmergencyProfile.query.filter_by(user_id=user_id).first()
            if not profile:
                profile = EmergencyProfile(user_id=user_id)
            
            for field in ['blood_type', 'allergies', 'medical_conditions', 'current_medications',
                         'emergency_contact_name', 'emergency_contact_phone', 'secondary_contact_name',
                         'secondary_contact_phone', 'primary_doctor_name', 'primary_doctor_phone',
                         'primary_doctor_hospital', 'organ_donor']:
                if field in data:
                    setattr(profile, field, data[field])
            
            profile.updated_at = datetime.utcnow()
            
            if profile.id is None:
                db.session.add(profile)
            
            db.session.commit()
            
            log_user_action(user_id, 'emergency_profile_update', 'Updated emergency profile')
            
            return jsonify({
                'message': 'Emergency profile updated successfully',
                'profile': profile.to_dict()
            }), 200
            
    except Exception as e:
        return jsonify({'error': f'Emergency profile operation failed: {str(e)}'}), 500

# QR Code Routes
@app.route('/api/qr/generate', methods=['POST'])
@jwt_required()
def generate_qr():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        access_type = data.get('access_type', 'emergency')
        expires_hours = data.get('expires_hours', 24)
        
        qr_token = secrets.token_urlsafe(32)
        
        qr_record = QRCodeRecord(
            user_id=user_id,
            qr_token=qr_token,
            access_type=access_type,
            expires_at=datetime.utcnow() + timedelta(hours=expires_hours)
        )
        
        db.session.add(qr_record)
        db.session.commit()
        
        qr_data = {
            'token': qr_token,
            'user_id': user_id,
            'access_type': access_type,
            'url': url_for('qr_access', token=qr_token, _external=True)
        }
        
        qr_image_base64 = generate_qr_code(json.dumps(qr_data))
        
        log_user_action(user_id, 'qr_generation', f'Generated {access_type} QR code')
        
        return jsonify({
            'message': 'QR code generated successfully',
            'qr_token': qr_token,
            'qr_image': f'data:image/png;base64,{qr_image_base64}',
            'expires_at': qr_record.expires_at.isoformat(),
            'access_url': qr_data['url']
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'QR code generation failed: {str(e)}'}), 500

@app.route('/api/qr/access/<token>')
def qr_access(token):
    try:
        qr_record = QRCodeRecord.query.filter_by(qr_token=token, is_active=True).first()
        
        if not qr_record:
            return jsonify({'error': 'Invalid QR code'}), 404
        
        if qr_record.expires_at and qr_record.expires_at < datetime.utcnow():
            return jsonify({'error': 'QR code has expired'}), 401
        
        user = User.query.get(qr_record.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        qr_record.last_used = datetime.utcnow()
        db.session.commit()
        
        log_user_action(qr_record.user_id, 'qr_access', f'QR code accessed via token: {token}')
        
        if qr_record.access_type == 'emergency':
            emergency_profile = EmergencyProfile.query.filter_by(user_id=qr_record.user_id).first()
            
            return jsonify({
                'user': {
                    'full_name': user.full_name,
                    'email': user.email
                },
                'emergency_profile': emergency_profile.to_dict() if emergency_profile else {},
                'access_type': 'emergency'
            }), 200
        else:
            return jsonify({
                'user': user.to_dict(),
                'access_type': 'full_access',
                'message': 'Use this token to access medical files via API'
            }), 200
            
    except Exception as e:
        return jsonify({'error': f'QR access failed: {str(e)}'}), 500

# Dashboard Routes
@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.account_type == 'patient':
            total_files = MedicalFile.query.filter_by(user_id=user_id).count()
            recent_files = MedicalFile.query.filter_by(user_id=user_id)\
                .filter(MedicalFile.upload_date >= datetime.utcnow() - timedelta(days=30)).count()
            
            recent_logs = AccessLog.query.filter_by(user_id=user_id)\
                .order_by(AccessLog.timestamp.desc()).limit(10).all()
            
            stats = {
                'total_files': total_files,
                'recent_files': recent_files,
                'last_login': recent_logs[0].timestamp.isoformat() if recent_logs else None,
                'recent_activity': [log.to_dict() for log in recent_logs]
            }
        else:
            stats = {
                'total_patients': 0,
                'appointments_today': 0,
                'pending_reviews': 0,
                'access_requests': 0
            }
        
        return jsonify({
            'user': user.to_dict(),
            'stats': stats
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get dashboard stats: {str(e)}'}), 500

# Health check route
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create sample data if none exists
        if not User.query.first():
            patient = User(
                email='sakshi@example.com',
                full_name='Sakshi Verma',
                account_type='patient'
            )
            patient.set_password('password123')
            
            doctor = User(
                email='dr.sharma@example.com',
                full_name='Dr. Raj Sharma',
                account_type='doctor',
                license_number='MD123456'
            )
            doctor.set_password('doctor123')
            
            db.session.add(patient)
            db.session.add(doctor)
            db.session.commit()
            
            emergency_profile = EmergencyProfile(
                user_id=patient.id,
                blood_type='O+',
                allergies='Penicillin (Severe), Shellfish, Latex',
                medical_conditions='Type 1 Diabetes (since age 12), Asthma',
                current_medications='Insulin Glargine - 20 units daily, Albuterol Inhaler - as needed, Lisinopril - 10mg daily',
                emergency_contact_name='Jay Gupta',
                emergency_contact_phone='+91 90348 74362',
                secondary_contact_name='Shreeya Singh',
                secondary_contact_phone='+91 98704 35332',
                primary_doctor_name='Dr. Moksh, MD',
                primary_doctor_phone='+91 78983 76483',
                primary_doctor_hospital='City General Hospital',
                organ_donor=True
            )
            
            db.session.add(emergency_profile)
            db.session.commit()
    
    app.run(host='localhost', port=8000, debug=True)