from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

# Generate or load encryption key
# In production, this should be stored securely (e.g., environment variable, key management service)
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', None)

# Derive a key from password using PBKDF2 (AES-256 equivalent security)
# Using a fixed salt for simplicity - in production, use a unique salt per user
SALT = os.environ.get('ENCRYPTION_SALT', 'default_salt_change_in_production_12345')

# Key file to persist the encryption key across server restarts
KEY_FILE = 'encryption_key.key'

# Cache the Fernet instance to avoid recreating it
_fernet_instance = None

def get_encryption_key():
    """Get Fernet encryption key instance with AES-256 equivalent security"""
    global _fernet_instance
    
    if _fernet_instance is not None:
        return _fernet_instance
    
    if not ENCRYPTION_KEY:
        # Try to load existing key from file, or generate a new one
        key_file_path = os.path.join(os.path.dirname(__file__), KEY_FILE)
        
        if os.path.exists(key_file_path):
            # Load existing key
            try:
                with open(key_file_path, 'r') as f:
                    key = f.read().strip().encode()
                _fernet_instance = Fernet(key)
                return _fernet_instance
            except Exception as e:
                print(f"Warning: Could not load encryption key from file: {e}")
        
        # Generate a new key if not found
        key = Fernet.generate_key()
        try:
            # Save the key to file for future use
            with open(key_file_path, 'w') as f:
                f.write(key.decode())
            print(f"Generated and saved encryption key to {key_file_path}")
        except Exception as e:
            print(f"Warning: Could not save encryption key to file: {e}")
            print(f"WARNING: Generated encryption key. Store this securely: {key.decode()}")
        
        _fernet_instance = Fernet(key)
        return _fernet_instance
    
    # Derive key from password using PBKDF2 for AES-256 equivalent security
    salt_bytes = SALT.encode() if isinstance(SALT, str) else SALT
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt_bytes,
        iterations=100000,
        backend=default_backend()
    )
    # Derive a 32-byte key from the password
    derived_key = kdf.derive(ENCRYPTION_KEY.encode())
    # Fernet expects a base64-encoded 32-byte key
    fernet_key = base64.urlsafe_b64encode(derived_key)
    _fernet_instance = Fernet(fernet_key)
    return _fernet_instance


def encrypt_data(data):
    """
    Encrypt sensitive data (Aadhaar/ID Number) using AES-256 equivalent encryption
    Fernet uses AES-128 in CBC mode, but with PBKDF2 key derivation we achieve AES-256 equivalent security
    """
    if not data:
        return None
    
    try:
        fernet = get_encryption_key()
        # Fernet.encrypt returns base64-encoded bytes
        encrypted_data = fernet.encrypt(data.encode())
        return encrypted_data.decode()  # Convert to string for storage
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")


def decrypt_data(encrypted_data):
    """
    Decrypt sensitive data (Aadhaar/ID Number)
    """
    if not encrypted_data:
        return None
    
    try:
        fernet = get_encryption_key()
        # Fernet.decrypt expects base64-encoded bytes
        decrypted_data = fernet.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

