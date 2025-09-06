# MediVault - Secure Digital Medical Records System

## Project Overview
MediVault is a complete blockchain-based digital medical records management system with a secure backend API and modern frontend interface. The application provides user authentication, file uploads, secure storage/retrieval, QR code generation, and blockchain simulation features.

## Architecture
- **Frontend**: HTML5, CSS3, Tailwind CSS, JavaScript
- **Backend**: Flask (Python) with SQLite database
- **Authentication**: Email/password + Google OAuth2 integration
- **File Storage**: Local filesystem with secure file handling
- **Blockchain**: Simulated blockchain for file integrity
- **Deployment**: Proxy server architecture serving on port 5000

## Key Features Implemented

### Authentication System
- Email/password registration and login
- Google OAuth2 integration (configured with client credentials)
- Separate patient and doctor account types
- Session management with localStorage

### File Management
- Secure file uploads with validation
- File categorization and metadata
- Download functionality
- Blockchain hash generation for integrity

### Emergency Profile System
- Complete medical information storage
- Emergency contact details
- Medical history and current medications
- Organ donor status tracking

### QR Code System
- Generate emergency access QR codes
- Time-limited access tokens
- Emergency information sharing
- Downloadable QR codes

### Dashboard Features
- User-specific file management
- Activity logs and statistics
- Profile management
- Real-time data from backend

## Database Schema
- **users**: User accounts with authentication details
- **medical_files**: File metadata and blockchain records
- **emergency_profiles**: Medical emergency information
- **access_logs**: System activity tracking
- **qr_codes**: QR code tokens and access control

## API Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User authentication
- `POST /api/files/upload` - File upload
- `GET /api/files/{user_id}` - Get user files
- `GET /api/files/download/{file_id}` - Download file
- `GET/POST /api/emergency-profile/{user_id}` - Emergency profile management
- `POST /api/qr/generate` - Generate QR codes
- `GET /api/qr/access/{token}` - QR code access
- `GET /api/dashboard/stats/{user_id}` - Dashboard statistics
- `GET /api/health` - Health check

## Sample Data
The system includes pre-configured sample accounts:
- **Patient**: sakshi@example.com / password123
- **Doctor**: dr.sharma@example.com / doctor123

## Technical Implementation
- **Backend**: `simple_app.py` - Main Flask application
- **Frontend API**: `medivault-api.js` - JavaScript integration layer
- **Proxy Server**: `proxy_server.py` - Serves frontend and routes API calls
- **Database**: SQLite with automatic initialization and sample data

## Security Features
- Password hashing with werkzeug security
- File type validation and secure naming
- CORS protection
- Access logging and monitoring
- Blockchain simulation for data integrity

## Current Status
✅ Complete backend implementation with all required endpoints
✅ Database schema and sample data configured
✅ Authentication system with Google OAuth
✅ File upload and management system
✅ Emergency profile management
✅ QR code generation and access
✅ Frontend-backend integration through JavaScript API
✅ Proxy server architecture for unified deployment

## Recent Changes (September 6, 2025)
- Implemented complete Flask backend with SQLite database
- Added Google OAuth2 authentication alongside email/password
- Created comprehensive API endpoint coverage
- Built JavaScript integration layer for frontend-backend communication
- Configured proxy server for unified deployment on port 5000
- Added sample data for immediate testing and demonstration

## User Preferences
- Prioritize security and data integrity
- Maintain clean, professional UI/UX
- Ensure all forms connect to proper backend endpoints
- Implement blockchain simulation for medical record integrity
- Support both patient and healthcare provider workflows