from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from models import db, User
from encryption import encrypt_data, decrypt_data
import os
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)

# JWT Error Handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': f'Invalid token: {str(error)}'}), 422
    return jsonify({'error': f'Invalid token: {str(error)}'}), 422

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': f'Authorization header is missing: {str(error)}'}), 401

CORS(app, resources={r"/api/*": {"origins": "*", "allow_headers": ["Content-Type", "Authorization"], "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]}})
db.init_app(app)

# Initialize database
with app.app_context():
    db.create_all()


# Validation functions
def validate_aadhaar(aadhaar):
    """Validate that Aadhaar is exactly 12 digits"""
    if not aadhaar:
        return None  # Optional field
    if not re.match(r'^\d{12}$', str(aadhaar).strip()):
        return 'Aadhaar must be exactly 12 digits'
    return None


def validate_phone(phone):
    """Validate that phone number is exactly 10 digits"""
    if not phone:
        return None  # Optional field
    if not re.match(r'^\d{10}$', str(phone).strip()):
        return 'Phone number must be exactly 10 digits'
    return None


def validate_date_of_birth(date_str):
    """Validate that date of birth is not in the future"""
    if not date_str:
        return None  # Optional field
    try:
        # Try to parse the date (supports formats: YYYY-MM-DD or other common formats)
        dob = datetime.strptime(str(date_str).strip(), '%Y-%m-%d').date()
        if dob > datetime.now().date():
            return 'Date of birth cannot be in the future'
    except ValueError:
        return 'Invalid date format. Please use YYYY-MM-DD'
    return None


@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Validate phone number if provided
        if data.get('phone'):
            phone_error = validate_phone(data['phone'])
            if phone_error:
                return jsonify({'error': phone_error}), 400
        
        # Validate aadhaar if provided
        if data.get('aadhaar_id'):
            aadhaar_error = validate_aadhaar(data['aadhaar_id'])
            if aadhaar_error:
                return jsonify({'error': aadhaar_error}), 400
        
        # Validate date of birth if provided
        if data.get('date_of_birth'):
            dob_error = validate_date_of_birth(data['date_of_birth'])
            if dob_error:
                return jsonify({'error': dob_error}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'User already exists'}), 400
        
        # Encrypt Aadhaar/ID Number if provided
        encrypted_aadhaar = None
        if data.get('aadhaar_id'):
            encrypted_aadhaar = encrypt_data(data['aadhaar_id'])
        
        # Create new user
        new_user = User(
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            full_name=data.get('full_name', ''),
            phone=data.get('phone', ''),
            address=data.get('address', ''),
            aadhaar_id_encrypted=encrypted_aadhaar,
            date_of_birth=data.get('date_of_birth', '')
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Generate JWT token (identity must be a string in Flask-JWT-Extended 4.x)
        access_token = create_access_token(identity=str(new_user.id))
        
        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user_id': new_user.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500


@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Generate JWT token (identity must be a string in Flask-JWT-Extended 4.x)
        access_token = create_access_token(identity=str(user.id))
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user_id': user.id
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500


@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        # get_jwt_identity() returns a string, convert to int for database query
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Decrypt Aadhaar/ID Number
        decrypted_aadhaar = None
        decryption_error = None
        if user.aadhaar_id_encrypted:
            try:
                decrypted_aadhaar = decrypt_data(user.aadhaar_id_encrypted)
            except Exception as e:
                # Log the error but don't fail the entire request
                decryption_error = f'Could not decrypt Aadhaar/ID data. This may happen if the encryption key changed. Error: {str(e)}'
                print(f"Decryption warning for user {user_id}: {decryption_error}")
                # Return None so the profile can still be displayed
                decrypted_aadhaar = None
        
        response_data = {
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'phone': user.phone,
            'address': user.address,
            'aadhaar_id': decrypted_aadhaar,
            'date_of_birth': user.date_of_birth,
            'created_at': user.created_at.isoformat() if user.created_at else None
        }
        
        # Include decryption warning if decryption failed
        if decryption_error:
            response_data['decryption_warning'] = decryption_error
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to fetch profile: {str(e)}'}), 500


@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        # get_jwt_identity() returns a string, convert to int for database query
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        # Validate phone number if provided
        if data.get('phone') is not None and data.get('phone'):
            phone_error = validate_phone(data['phone'])
            if phone_error:
                return jsonify({'error': phone_error}), 400
        
        # Validate aadhaar if provided
        if data.get('aadhaar_id') is not None and data.get('aadhaar_id'):
            aadhaar_error = validate_aadhaar(data['aadhaar_id'])
            if aadhaar_error:
                return jsonify({'error': aadhaar_error}), 400
        
        # Validate date of birth if provided
        if data.get('date_of_birth') is not None and data.get('date_of_birth'):
            dob_error = validate_date_of_birth(data['date_of_birth'])
            if dob_error:
                return jsonify({'error': dob_error}), 400
        
        # Update fields if provided
        if data.get('full_name') is not None:
            user.full_name = data['full_name']
        if data.get('phone') is not None:
            user.phone = data['phone']
        if data.get('address') is not None:
            user.address = data['address']
        if data.get('date_of_birth') is not None:
            user.date_of_birth = data['date_of_birth']
        
        # Handle Aadhaar/ID - re-encrypt with current key
        if data.get('aadhaar_id') is not None:
            if data['aadhaar_id']:
                # Encrypt with current key
                user.aadhaar_id_encrypted = encrypt_data(data['aadhaar_id'])
            else:
                # Clear if empty string
                user.aadhaar_id_encrypted = None
        
        db.session.commit()
        
        # Return updated profile
        decrypted_aadhaar = None
        if user.aadhaar_id_encrypted:
            try:
                decrypted_aadhaar = decrypt_data(user.aadhaar_id_encrypted)
            except Exception as e:
                print(f"Warning: Could not decrypt after update: {str(e)}")
        
        return jsonify({
            'message': 'Profile updated successfully',
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'phone': user.phone,
            'address': user.address,
            'aadhaar_id': decrypted_aadhaar,
            'date_of_birth': user.date_of_birth,
            'created_at': user.created_at.isoformat() if user.created_at else None
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update profile: {str(e)}'}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200


if __name__ == '__main__':
    app.run(debug=True, port=5000)

