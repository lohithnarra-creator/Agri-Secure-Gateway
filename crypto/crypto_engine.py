"""
AGRI-SECURE GATEWAY - Cryptographic Engine
Core security implementations:
1. RSA-2048 Digital Signatures (Asymmetric Authentication & Non-Repudiation)
2. SHA-256 Cryptographic Hash Digest (Binary Integrity Verification & Avalanche Effect)
3. AES-256-GCM Authenticated Symmetric Encryption (Confidentiality & Tag Verification)
"""

import os
import base64
import hashlib
import hmac
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature, InvalidTag

# Keys directory path
KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'keys'))
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, 'vendor_private_key.pem')
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, 'vendor_public_key.pem')
AES_KEY_PATH = os.path.join(KEYS_DIR, 'firmware_aes_256.key')


def init_crypto_keys(force_rotate: bool = False):
    """
    Ensures that vendor RSA-2048 keypair and AES-256 master key exist on disk.
    Supports environment variables (RSA_PRIVATE_KEY_PEM, RSA_PUBLIC_KEY_PEM, AES_SECRET_KEY_HEX)
    for persistent cloud deployments (e.g. Render).
    Generates cryptographically strong keys if they are missing or if force_rotate is True.
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

    # Cloud / Environment variable injection for persistence across redeployments
    env_priv = os.environ.get('RSA_PRIVATE_KEY_PEM')
    env_pub = os.environ.get('RSA_PUBLIC_KEY_PEM')
    env_aes = os.environ.get('AES_SECRET_KEY_HEX')

    if env_priv and env_pub and not force_rotate:
        priv_bytes = env_priv.replace('\\n', '\n').encode('utf-8')
        pub_bytes = env_pub.replace('\\n', '\n').encode('utf-8')
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(priv_bytes)
        try:
            os.chmod(PRIVATE_KEY_PATH, 0o600)
        except Exception:
            pass
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(pub_bytes)

    if env_aes and not force_rotate:
        try:
            aes_bytes = bytes.fromhex(env_aes.strip())
            if len(aes_bytes) == 32:
                with open(AES_KEY_PATH, 'wb') as f:
                    f.write(aes_bytes)
                try:
                    os.chmod(AES_KEY_PATH, 0o600)
                except Exception:
                    pass
        except Exception:
            pass

    # 1. RSA-2048 Vendor Keypair
    if force_rotate or not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(private_pem)
        try:
            os.chmod(PRIVATE_KEY_PATH, 0o600)  # Restrict private key permissions
        except Exception:
            pass

        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(public_pem)

    # 2. AES-256 Key (32 bytes = 256 bits)
    if force_rotate or not os.path.exists(AES_KEY_PATH):
        aes_key = os.urandom(32)
        with open(AES_KEY_PATH, 'wb') as f:
            f.write(aes_key)
        try:
            os.chmod(AES_KEY_PATH, 0o600)
        except Exception:
            pass


def get_private_key():
    """Load RSA private key from disk (server-side only, never exposed to client)."""
    init_crypto_keys()
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def get_public_key():
    """Load RSA public key from disk."""
    init_crypto_keys()
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def get_public_key_pem() -> str:
    """Return public key in PEM string format."""
    init_crypto_keys()
    with open(PUBLIC_KEY_PATH, 'r', encoding='utf-8') as f:
        return f.read()


def get_public_key_fingerprint() -> str:
    """
    Computes standard SHA-256 fingerprint of the SubjectPublicKeyInfo.
    Format: RSA-2048: SHA256:xx:xx:xx:...
    """
    init_crypto_keys()
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        key_bytes = f.read()
    digest = hashlib.sha256(key_bytes).hexdigest()
    colon_format = ':'.join(digest[i:i+2] for i in range(0, 16, 2))
    return f"RSA-2048: SHA256:{colon_format}"


def get_aes_key() -> bytes:
    """Return the 256-bit AES symmetric key from storage."""
    init_crypto_keys()
    with open(AES_KEY_PATH, 'rb') as f:
        return f.read()


def rotate_rsa_keypair() -> dict:
    """Regenerates a fresh RSA-2048 keypair and returns new fingerprint."""
    init_crypto_keys(force_rotate=True)
    return {
        'success': True,
        'message': 'RSA-2048 vendor keypair successfully regenerated and rotated.',
        'fingerprint': get_public_key_fingerprint(),
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


# ==============================================================================
# 1. SHA-256 Integrity Operations
# ==============================================================================

def calculate_sha256(data: bytes) -> str:
    """
    Computes actual SHA-256 hex digest of arbitrary binary data (firmware).
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def verify_sha256(data: bytes, expected_hash: str) -> bool:
    """
    Constant-time comparison of SHA-256 digest to prevent timing attacks.
    """
    computed_hash = calculate_sha256(data)
    return hmac.compare_digest(computed_hash.lower(), expected_hash.strip().lower())


# ==============================================================================
# 2. RSA-2048 Digital Signatures (PKCS#1 v1.5 with SHA-256)
# ==============================================================================

def sign_firmware(firmware_bytes: bytes) -> dict:
    """
    Signs firmware bytes using vendor's RSA-2048 private key.
    Calculates SHA-256 digest and performs asymmetric signing.
    Returns dictionary with hash, base64 signature, and metadata.
    """
    if isinstance(firmware_bytes, str):
        firmware_bytes = firmware_bytes.encode('utf-8')

    private_key = get_private_key()
    sha256_hash = calculate_sha256(firmware_bytes)

    # Sign using RSA-PKCS1v15 padding with SHA-256
    raw_signature = private_key.sign(
        firmware_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    signature_b64 = base64.b64encode(raw_signature).decode('utf-8')

    return {
        'success': True,
        'sha256_hash': sha256_hash,
        'signature_b64': signature_b64,
        'signature_len_bytes': len(raw_signature),
        'key_size_bits': 2048,
        'algorithm': 'RSA-2048 / PKCS#1 v1.5 / SHA-256',
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def verify_firmware_signature(firmware_bytes: bytes, signature_b64: str) -> dict:
    """
    Verifies firmware bytes against an RSA-2048 signature using the vendor's public key.
    Detects any byte alterations or forged signatures.
    """
    if isinstance(firmware_bytes, str):
        firmware_bytes = firmware_bytes.encode('utf-8')

    public_key = get_public_key()
    computed_sha256 = calculate_sha256(firmware_bytes)

    try:
        raw_signature = base64.b64decode(signature_b64)
    except Exception as e:
        return {
            'valid': False,
            'computed_sha256': computed_sha256,
            'error': f'Base64 decoding failed: {str(e)}',
            'message': 'REJECTED: Malformed digital signature format.'
        }

    try:
        public_key.verify(
            raw_signature,
            firmware_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return {
            'valid': True,
            'computed_sha256': computed_sha256,
            'fingerprint': get_public_key_fingerprint(),
            'message': 'VERIFIED: Digital signature matches vendor root authority. Firmware origin and integrity verified.'
        }
    except InvalidSignature:
        return {
            'valid': False,
            'computed_sha256': computed_sha256,
            'fingerprint': get_public_key_fingerprint(),
            'message': 'REJECTED: Cryptographic signature mismatch! Firmware has been tampered with or signed by an untrusted key.'
        }
    except Exception as e:
        return {
            'valid': False,
            'computed_sha256': computed_sha256,
            'error': str(e),
            'message': f'REJECTED: Signature verification failed: {str(e)}'
        }


# ==============================================================================
# 3. AES-256 Authenticated Symmetric Encryption (GCM with 96-bit Nonce & 128-bit Tag)
# ==============================================================================

def encrypt_firmware_aes256_gcm(firmware_bytes: bytes, custom_key: bytes = None) -> dict:
    """
    Encrypts firmware bytes using AES-256 in GCM (Galois/Counter Mode).
    Generates a secure 12-byte (96-bit) random nonce and 16-byte authentication tag.
    Provides authenticated encryption (Confidentiality + Authenticity).
    """
    if isinstance(firmware_bytes, str):
        firmware_bytes = firmware_bytes.encode('utf-8')

    key = custom_key or get_aes_key()
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")

    # Generate standard 12-byte (96-bit) GCM nonce
    nonce = os.urandom(12)

    # Initialize AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(firmware_bytes) + encryptor.finalize()
    tag = encryptor.tag  # 16-byte authentication tag

    return {
        'success': True,
        'ciphertext_b64': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce_b64': base64.b64encode(nonce).decode('utf-8'),
        'tag_b64': base64.b64encode(tag).decode('utf-8'),
        'ciphertext_hex': ciphertext.hex(),
        'nonce_hex': nonce.hex(),
        'tag_hex': tag.hex(),
        'ciphertext_len': len(ciphertext),
        'plaintext_len': len(firmware_bytes),
        'cipher_mode': 'AES-256-GCM (Authenticated)',
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def decrypt_firmware_aes256_gcm(ciphertext_b64: str, nonce_b64: str, tag_b64: str, key: bytes = None) -> dict:
    """
    Decrypts AES-256-GCM ciphertext and validates the 16-byte authentication tag.
    If even 1 bit of ciphertext or tag is modified, InvalidTag is raised.
    """
    key = key or get_aes_key()
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
    except Exception as e:
        return {'success': False, 'message': f'Base64 decoding failed: {str(e)}'}

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return {
            'success': True,
            'plaintext': plaintext.decode('utf-8', errors='replace'),
            'message': 'Decryption and authentication tag validation succeeded.'
        }
    except InvalidTag:
        return {
            'success': False,
            'message': 'AUTHENTICATION TAG MISMATCH: Decryption rejected. Ciphertext or tag has been tampered with.'
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Decryption failed: {str(e)}'
        }


# Legacy compatibility wrappers (CBC)
def encrypt_firmware_aes256(firmware_bytes: bytes, custom_key: bytes = None) -> dict:
    return encrypt_firmware_aes256_gcm(firmware_bytes, custom_key)


def decrypt_firmware_aes256(ciphertext_b64: str, iv_b64: str, key: bytes = None) -> bytes:
    # If called with legacy signature, fallback gracefully
    key = key or get_aes_key()
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()
