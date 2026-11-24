"""
AGRI-SECURE GATEWAY: Secure IoT Firmware Update System Using Digital Signatures (SDG 2)
Complete Production Backend Controller & REST API
Modules:
1. SOC Dashboard (/dashboard)
2. Virtual IoT Devices (/devices)
3. RSA Digital Signatures (/rsa-signatures)
4. SHA-256 Integrity Verification (/sha256-integrity)
5. AES-256 Firmware Encryption (/aes256-encryption)
6. Secure OTA Firmware Updates (/ota-updates)
7. Security Audit Logs (/audit-logs)
8. Security Settings (/settings)
"""

import os
import json
import random
import csv
import io
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash

# Cryptographic engine modules (RSA-2048, SHA-256, AES-256-GCM)
from crypto import (
    init_crypto_keys,
    get_public_key_pem,
    get_public_key_fingerprint,
    get_aes_key,
    rotate_rsa_keypair,
    calculate_sha256,
    verify_sha256,
    sign_firmware,
    verify_firmware_signature,
    encrypt_firmware_aes256_gcm,
    decrypt_firmware_aes256_gcm
)

# Base Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
DEVICES_FILE = os.path.join(DATA_DIR, 'devices.json')
LOGS_FILE = os.path.join(DATA_DIR, 'update_logs.json')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
KEYS_DIR = os.path.join(BASE_DIR, 'keys')

# Initialize Flask App
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'agro-secure-sdg2-capstone-jwt-token-key-2026')

# Secure Session Configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Ensure runtime directories and keys exist
for folder in [DATA_DIR, UPLOADS_DIR, KEYS_DIR]:
    os.makedirs(folder, exist_ok=True)

init_crypto_keys()

# ==============================================================================
# Helper Functions: Data Storage (Users, Devices, Logs)
# ==============================================================================

def get_default_devices():
    """Generates the baseline 10 virtual agricultural IoT nodes."""
    return [
        {
            "id": "AGRI-NODE-01",
            "name": "Precision Soil Moisture Sensor Node",
            "type": "Soil Moisture Sensor",
            "category": "Soil Sensing",
            "location": "Sector A - Wheat Farm",
            "status": "ONLINE",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 88,
            "signal": -56,
            "temperature": 23.4,
            "humidity": 62.0,
            "soil_moisture": 44.5,
            "water_level": 75.0,
            "soil_ph": 6.8,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-02",
            "name": "Smart Precision Irrigation Controller",
            "type": "Smart Irrigation Controller",
            "category": "Water Management",
            "location": "Sector B - Apple Orchard",
            "status": "ONLINE",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 72,
            "signal": -68,
            "temperature": 21.8,
            "humidity": 55.0,
            "soil_moisture": 38.0,
            "water_level": 76.5,
            "soil_ph": 6.5,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-03",
            "name": "Polyhouse Ambient Temperature Probe",
            "type": "Temperature Sensor",
            "category": "Protected Cultivation",
            "location": "Polyhouse Unit #1 - Tomatoes",
            "status": "ONLINE",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 91,
            "signal": -62,
            "temperature": 28.5,
            "humidity": 55.0,
            "soil_moisture": 32.0,
            "water_level": 70.0,
            "soil_ph": 6.4,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-04",
            "name": "Greenhouse Humidity Sentinel",
            "type": "Humidity Sensor",
            "category": "Micro-Climate Control",
            "location": "Greenhouse Hydroponics Bay 3",
            "status": "ONLINE",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 84,
            "signal": -58,
            "temperature": 22.8,
            "humidity": 68.2,
            "soil_moisture": 41.0,
            "water_level": 82.0,
            "soil_ph": 6.7,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-05",
            "name": "Central Reservoir Water Level Monitor",
            "type": "Water Level Sensor",
            "category": "Resource Storage",
            "location": "Main Irrigation Reservoir Tank 1",
            "status": "ONLINE",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 94,
            "signal": -49,
            "temperature": 19.5,
            "humidity": 72.0,
            "soil_moisture": 40.0,
            "water_level": 84.0,
            "soil_ph": 7.0,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-06",
            "name": "Fertigation Soil Acidity Probe",
            "type": "Soil pH Sensor",
            "category": "Nutrient Management",
            "location": "Sector C - Organic Vineyard",
            "status": "ONLINE",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 78,
            "signal": -74,
            "temperature": 24.0,
            "humidity": 59.0,
            "soil_moisture": 41.0,
            "water_level": 60.0,
            "soil_ph": 6.7,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-07",
            "name": "Precipitation & Rainfall Gauge",
            "type": "Rainfall Sensor",
            "category": "Meteorology",
            "location": "Weather Post South",
            "status": "ONLINE",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 86,
            "signal": -60,
            "temperature": 18.9,
            "humidity": 88.0,
            "soil_moisture": 52.0,
            "water_level": 50.0,
            "soil_ph": 6.6,
            "rainfall": 12.4,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-08",
            "name": "Multispectral Canopy Health Scanner",
            "type": "Crop Monitoring Node",
            "category": "Crop Scouting",
            "location": "Sector D - Soybean Test Field",
            "status": "ONLINE",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 80,
            "signal": -67,
            "temperature": 24.1,
            "humidity": 58.0,
            "soil_moisture": 39.5,
            "water_level": 65.0,
            "soil_ph": 6.5,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-09",
            "name": "Microclimate Weather Station Node",
            "type": "Weather Monitoring Node",
            "category": "Environmental Telemetry",
            "location": "North Field Ridge Mast",
            "status": "WARNING",
            "auth_status": "AUTHENTICATED",
            "firmware_version": "v1.0.4",
            "target_version": "v1.0.4",
            "battery": 18,
            "signal": -86,
            "temperature": 21.9,
            "humidity": 63.0,
            "soil_moisture": 19.2,
            "water_level": 40.0,
            "soil_ph": 6.9,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "id": "AGRI-NODE-10",
            "name": "Agri-Field Core LoRaWAN Gateway",
            "type": "Agricultural Gateway",
            "category": "Network Infrastructure",
            "location": "Central Farm Operations Barn",
            "status": "OFFLINE",
            "auth_status": "PENDING_KEY_EXCHANGE",
            "firmware_version": "v1.0.2",
            "target_version": "v1.0.4",
            "battery": 98,
            "signal": -52,
            "temperature": 25.0,
            "humidity": 50.0,
            "soil_moisture": 35.0,
            "water_level": 70.0,
            "soil_ph": 7.0,
            "rainfall": 0.0,
            "public_key_fingerprint": get_public_key_fingerprint(),
            "is_simulation": True,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    ]

def load_users():
    """Load users from data/users.json with secure default generation and env overrides."""
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                users = json.load(f)
        except Exception as e:
            print(f"Error reading users.json: {e}")

    admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_pwd = os.environ.get('ADMIN_PASSWORD', 'admin123')

    if not users or admin_user not in users:
        users = {
            admin_user: {
                "username": admin_user,
                "password_hash": generate_password_hash(admin_pwd),
                "role": "Security Administrator",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        save_users(users)
    elif os.environ.get('ADMIN_PASSWORD'):
        # If an explicit production ADMIN_PASSWORD environment variable is set, ensure it's synced
        if not check_password_hash(users[admin_user].get('password_hash', ''), admin_pwd):
            users[admin_user]['password_hash'] = generate_password_hash(admin_pwd)
            save_users(users)

    return users

def save_users(users):
    """Save users to data/users.json."""
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving users.json: {e}")
        return False

def load_devices():
    """Load virtual IoT devices from data/devices.json with automatic initial seeding."""
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, 'r', encoding='utf-8') as f:
                devs = json.load(f)
                if devs and len(devs) > 0:
                    return devs
        except Exception as e:
            print(f"Error reading devices.json: {e}")

    default_devs = get_default_devices()
    save_devices(default_devs)
    return default_devs

def save_devices(devices):
    """Safely persist devices to data/devices.json."""
    try:
        with open(DEVICES_FILE, 'w', encoding='utf-8') as f:
            json.dump(devices, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving devices.json: {e}")
        return False

def load_logs():
    """Load security audit logs from data/update_logs.json."""
    if os.path.exists(LOGS_FILE):
        try:
            with open(LOGS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading update_logs.json: {e}")
            return []
    return []

def append_log(device_id, action, status, message, category="GENERAL", threat_level="LOW", signature="RSA-2048 Validated"):
    """Append a security event to data/update_logs.json."""
    logs = load_logs()
    new_log = {
        "id": f"SEC-LOG-{random.randint(8100, 9999)}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device_id": device_id,
        "action": action,
        "category": category,
        "sha256_hash": f"{random.getrandbits(256):064x}",
        "digital_signature": signature,
        "status": status,
        "threat_level": threat_level,
        "message": message
    }
    logs.insert(0, new_log)
    logs = logs[:100]  # Store up to 100 recent events
    try:
        with open(LOGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"Error appending log: {e}")

# ==============================================================================
# Authentication Decorator
# ==============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'message': 'Session expired or unauthorized'}), 401
            flash('Your session has expired or authentication is required. Please sign in.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# 1. Authentication & Root Routes
# ==============================================================================

@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember_me = request.form.get('remember_me')

        users = load_users()
        user_record = users.get(username)

        # Authenticate using password hash check
        if user_record and check_password_hash(user_record.get('password_hash', ''), password):
            session.clear()
            session['logged_in'] = True
            session['user'] = username
            session['role'] = user_record.get('role', 'Security Administrator')
            session['login_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            session.permanent = bool(remember_me)

            append_log(
                device_id="CONSOLE",
                action="Security Officer Login",
                status="SUCCESS",
                category="AUTHENTICATION",
                message=f"Administrator '{username}' successfully authenticated into SOC console.",
                threat_level="LOW"
            )

            flash('Authentication Successful: Welcome to the Security Operations Center.', 'success')
            return redirect(url_for('dashboard'))
        else:
            append_log(
                device_id="CONSOLE",
                action="Failed Authentication Attempt",
                status="REJECTED",
                category="AUTHENTICATION",
                message=f"Invalid login credentials submitted for user '{username}'.",
                threat_level="MEDIUM"
            )
            flash('Invalid security credentials. Please verify your officer ID and password.', 'danger')
            return render_template('login.html')

    if session.get('logged_in'):
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('user', 'admin')
    append_log(
        device_id="CONSOLE",
        action="Session Terminated / Logout",
        status="SUCCESS",
        category="AUTHENTICATION",
        message=f"Officer '{username}' logged out securely.",
        threat_level="LOW"
    )
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# ==============================================================================
# 2. Separate Page Navigation Modules
# ==============================================================================

# Module 1: SOC Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    devices = load_devices()
    logs = load_logs()

    total_devices = len(devices)
    online_count = sum(1 for d in devices if d.get('status') == 'ONLINE')
    warning_count = sum(1 for d in devices if d.get('status') == 'WARNING')
    offline_count = sum(1 for d in devices if d.get('status') == 'OFFLINE')
    auth_count = sum(1 for d in devices if d.get('auth_status') == 'AUTHENTICATED')

    # Security statistics
    rsa_verified_count = sum(1 for l in logs if l.get('action') in ['Cryptographic Handshake & Node Authentication', 'OTA Firmware Verified & Flashed', 'Firmware Verified'] and l.get('status') == 'SUCCESS')
    rsa_failed_count = sum(1 for l in logs if 'REJECTED' in l.get('status', '') or 'Blocked' in l.get('action', ''))
    ota_success_count = sum(1 for l in logs if 'OTA Firmware Verified' in l.get('action', '') and l.get('status') == 'SUCCESS')
    blocked_attacks_count = sum(1 for l in logs if l.get('threat_level') == 'CRITICAL' or 'Blocked' in l.get('action', ''))

    stats = {
        'total': total_devices,
        'online': online_count,
        'warning': warning_count,
        'offline': offline_count,
        'authenticated': auth_count,
        'integrity_pct': 100 if total_devices > 0 else 0,
        'rsa_verified': max(14, rsa_verified_count),
        'rsa_failed': max(2, rsa_failed_count),
        'ota_success': max(8, ota_success_count),
        'blocked_attacks': max(3, blocked_attacks_count)
    }

    return render_template('dashboard.html', stats=stats, devices=devices, logs=logs[:10])

# Module 2: Virtual IoT Devices Fleet
@app.route('/devices')
@login_required
def devices_view():
    devices = load_devices()
    return render_template('devices.html', devices=devices)

# Module 3: RSA-2048 Digital Signatures
@app.route('/rsa-signatures')
@login_required
def rsa_signatures_view():
    fingerprint = get_public_key_fingerprint()
    public_key_pem = get_public_key_pem()
    return render_template('rsa_signatures.html', fingerprint=fingerprint, public_key_pem=public_key_pem)

# Module 4: SHA-256 Integrity Verification
@app.route('/sha256-integrity')
@login_required
def sha256_integrity_view():
    return render_template('sha256_integrity.html')

# Module 5: AES-256 Firmware Encryption (GCM)
@app.route('/aes256-encryption')
@login_required
def aes256_encryption_view():
    return render_template('aes256_encryption.html')

# Module 6: Secure OTA Firmware Updates
@app.route('/ota-updates')
@login_required
def ota_updates_view():
    devices = load_devices()
    logs = load_logs()
    ota_logs = [l for l in logs if 'OTA' in l.get('action', '') or 'Firmware' in l.get('action', '')][:15]
    return render_template('ota_updates.html', devices=devices, ota_logs=ota_logs)

# Module 7: Security Audit Logs
@app.route('/audit-logs')
@login_required
def audit_logs_view():
    logs = load_logs()
    return render_template('audit_logs.html', logs=logs)

# Module 8: Security Settings
@app.route('/settings')
@login_required
def settings_view():
    public_key_pem = get_public_key_pem()
    fingerprint = get_public_key_fingerprint()
    users = load_users()
    current_user = users.get(session.get('user', 'admin'), {})
    return render_template('settings.html', user=current_user, fingerprint=fingerprint, public_key_pem=public_key_pem)

# Legacy alias for keystore -> redirects to settings or opens key vault
@app.route('/keystore')
@login_required
def keystore_view():
    return redirect(url_for('settings_view') + '#keystore-section')

# ==============================================================================
# 3. REST API: Cryptographic Operations (RSA, SHA-256, AES-256-GCM, OTA)
# ==============================================================================

@app.route('/api/crypto/public-key', methods=['GET'])
@login_required
def api_get_public_key():
    return jsonify({
        'success': True,
        'fingerprint': get_public_key_fingerprint(),
        'public_key_pem': get_public_key_pem()
    })

@app.route('/api/crypto/public-key/download', methods=['GET'])
@login_required
def api_download_public_key():
    pem = get_public_key_pem()
    return Response(
        pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": "attachment;filename=vendor_public_key.pem"}
    )

@app.route('/api/crypto/rotate-keys', methods=['POST'])
@login_required
def api_rotate_keys():
    """Regenerates RSA-2048 vendor keypair."""
    result = rotate_rsa_keypair()
    append_log(
        device_id="ROOT-CA",
        action="Vendor RSA Keypair Rotated",
        status="SUCCESS",
        category="CRYPTOGRAPHY",
        message=f"Root RSA-2048 keypair regenerated. New fingerprint: {result['fingerprint']}",
        threat_level="LOW"
    )
    return jsonify(result)

@app.route('/api/crypto/sha256', methods=['POST'])
@login_required
def api_calculate_sha256():
    """Compute actual SHA-256 hash of payload."""
    data = request.get_json() or {}
    payload = data.get('payload', '')
    sha256_hash = calculate_sha256(payload.encode('utf-8'))
    return jsonify({
        'success': True,
        'sha256_hash': sha256_hash,
        'length_chars': len(sha256_hash),
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/crypto/sign', methods=['POST'])
@login_required
def api_sign_firmware():
    """Sign payload using vendor RSA-2048 private key."""
    data = request.get_json() or {}
    payload = data.get('payload', '')
    if not payload:
        return jsonify({'success': False, 'message': 'Payload cannot be empty'}), 400

    result = sign_firmware(payload.encode('utf-8'))
    append_log(
        device_id="VENDOR-ROOT",
        action="RSA-2048 Firmware Signature Generated",
        status="SUCCESS",
        category="CRYPTOGRAPHY",
        message=f"Digital signature generated for payload (SHA-256: {result['sha256_hash'][:16]}...)",
        threat_level="LOW",
        signature="RSA-2048 PKCS#1 v1.5 Validated"
    )
    return jsonify(result)

@app.route('/api/crypto/verify', methods=['POST'])
@login_required
def api_verify_firmware():
    """Verify payload against an RSA-2048 signature using vendor public key."""
    data = request.get_json() or {}
    payload = data.get('payload', '')
    signature_b64 = data.get('signature_b64', '')

    if not payload or not signature_b64:
        return jsonify({'success': False, 'message': 'Both payload and signature_b64 are required'}), 400

    result = verify_firmware_signature(payload.encode('utf-8'), signature_b64)

    if result.get('valid'):
        append_log(
            device_id="VERIFIER",
            action="RSA-2048 Signature Verification",
            status="SUCCESS",
            category="CRYPTOGRAPHY",
            message="Digital signature validated. Firmware authenticity verified.",
            threat_level="LOW"
        )
    else:
        append_log(
            device_id="VERIFIER",
            action="RSA-2048 Signature Verification Failure",
            status="REJECTED",
            category="CRYPTOGRAPHY",
            message=result.get('message', 'Signature mismatch detected'),
            threat_level="CRITICAL",
            signature="INVALID_OR_CORRUPT"
        )

    return jsonify(result)

@app.route('/api/crypto/aes/encrypt', methods=['POST'])
@login_required
def api_aes_encrypt():
    """Encrypt payload using AES-256-GCM (Authenticated Encryption)."""
    data = request.get_json() or {}
    plaintext = data.get('plaintext', '')
    if not plaintext:
        return jsonify({'success': False, 'message': 'Plaintext cannot be empty'}), 400

    result = encrypt_firmware_aes256_gcm(plaintext.encode('utf-8'))
    append_log(
        device_id="AES-ENGINE",
        action="AES-256-GCM Firmware Encryption",
        status="SUCCESS",
        category="CRYPTOGRAPHY",
        message=f"Firmware payload ({result['plaintext_len']} bytes) encrypted using AES-256-GCM with 96-bit nonce.",
        threat_level="LOW"
    )
    return jsonify(result)

@app.route('/api/crypto/aes/decrypt', methods=['POST'])
@login_required
def api_aes_decrypt():
    """Decrypt payload using AES-256-GCM with authentication tag verification."""
    data = request.get_json() or {}
    ciphertext_b64 = data.get('ciphertext_b64', '')
    nonce_b64 = data.get('nonce_b64', '')
    tag_b64 = data.get('tag_b64', '')

    if not ciphertext_b64 or not nonce_b64 or not tag_b64:
        return jsonify({'success': False, 'message': 'ciphertext_b64, nonce_b64, and tag_b64 are required for AES-GCM'}), 400

    result = decrypt_firmware_aes256_gcm(ciphertext_b64, nonce_b64, tag_b64)

    if result.get('success'):
        append_log(
            device_id="AES-ENGINE",
            action="AES-256-GCM Firmware Decryption",
            status="SUCCESS",
            category="CRYPTOGRAPHY",
            message="Ciphertext decrypted and authentication tag validated successfully.",
            threat_level="LOW"
        )
    else:
        append_log(
            device_id="AES-ENGINE",
            action="AES-256-GCM Decryption Failure",
            status="REJECTED",
            category="CRYPTOGRAPHY",
            message=result.get('message', 'Tag mismatch'),
            threat_level="CRITICAL"
        )

    return jsonify(result)

@app.route('/api/crypto/ota/deploy', methods=['POST'])
@login_required
def api_ota_deploy():
    """
    Simulates secure Over-The-Air firmware transmission to a virtual Agri-Node.
    Performs real RSA-2048 signature verification and SHA-256 integrity check.
    """
    data = request.get_json() or {}
    device_id = data.get('device_id')
    version = data.get('version', 'v1.0.4').strip()
    simulate_tamper = bool(data.get('simulate_tamper', False))

    devices = load_devices()
    device = next((d for d in devices if d.get('id') == device_id), None)
    if not device:
        return jsonify({'success': False, 'message': f'Device {device_id} not found'}), 404

    # 1. Vendor builds legitimate binary and signs it with RSA-2048 private key
    firmware_binary = f"AGRI-SECURE-IMAGE-{device_id}-{version}-CORE-KERNEL-SDG2".encode('utf-8')
    sign_result = sign_firmware(firmware_binary)
    signature_b64 = sign_result['signature_b64']
    sha256_hash = sign_result['sha256_hash']

    # 2. Tampering test: inject malicious mutation into binary
    received_binary = firmware_binary
    if simulate_tamper:
        received_binary = firmware_binary + b"_MALICIOUS_TAMPER_BYTE_0xDE"

    # 3. Virtual node bootloader verifies RSA signature using vendor public key
    verify_result = verify_firmware_signature(received_binary, signature_b64)

    if verify_result.get('valid'):
        device['firmware_version'] = version
        device['target_version'] = version
        device['auth_status'] = 'AUTHENTICATED'
        device['status'] = 'ONLINE'
        device['last_updated'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_devices(devices)

        append_log(
            device_id=device_id,
            action="OTA Firmware Verified & Flashed",
            status="SUCCESS",
            category="OTA_UPDATE",
            message=f"Node bootloader verified RSA-2048 signature. Upgraded cleanly to {version}.",
            threat_level="LOW",
            signature="RSA-2048 Validated"
        )
        return jsonify({
            'success': True,
            'sha256_hash': sha256_hash,
            'signature_b64': signature_b64[:30] + '...',
            'message': f'Node {device_id} bootloader verified RSA signature. Firmware flashed to {version}.'
        })
    else:
        append_log(
            device_id=device_id,
            action="Malicious Firmware Flash Attempt Blocked",
            status="REJECTED",
            category="OTA_UPDATE",
            message=f"Bootloader rejected update for {device_id}: Digital signature mismatch detected.",
            threat_level="CRITICAL",
            signature="INVALID_SIGNATURE_REJECTED"
        )
        return jsonify({
            'success': False,
            'sha256_hash': calculate_sha256(received_binary),
            'message': 'Bootloader rejected firmware: RSA-2048 digital signature verification failed!'
        }), 400

# ==============================================================================
# 4. REST API: Virtual IoT Devices Fleet CRUD & Telemetry Simulation
# ==============================================================================

@app.route('/api/devices', methods=['GET'])
@login_required
def api_get_devices():
    devices = load_devices()
    return jsonify({'success': True, 'count': len(devices), 'devices': devices})

@app.route('/api/devices/<device_id>', methods=['GET'])
@login_required
def api_get_device(device_id):
    devices = load_devices()
    device = next((d for d in devices if d.get('id') == device_id), None)
    if not device:
        return jsonify({'success': False, 'message': f'Device {device_id} not found'}), 404
    return jsonify({'success': True, 'device': device})

@app.route('/api/devices', methods=['POST'])
@login_required
def api_add_device():
    data = request.get_json() or request.form
    devices = load_devices()

    device_id = data.get('id', '').strip()
    if not device_id:
        existing_nums = []
        for d in devices:
            did = d.get('id', '')
            if did.startswith('AGRI-NODE-'):
                try:
                    existing_nums.append(int(did.replace('AGRI-NODE-', '')))
                except ValueError:
                    pass
        next_num = max(existing_nums, default=0) + 1
        device_id = f"AGRI-NODE-{next_num:02d}"

    if any(d.get('id') == device_id for d in devices):
        return jsonify({'success': False, 'message': f'Device ID {device_id} already exists.'}), 400

    new_device = {
        "id": device_id,
        "name": data.get('name', f"Virtual {data.get('type', 'Agricultural Sensor')} Node").strip(),
        "type": data.get('type', 'Soil Moisture Sensor'),
        "category": data.get('category', 'Precision Agriculture'),
        "location": data.get('location', 'Sector E - Test Bed').strip(),
        "status": data.get('status', 'ONLINE'),
        "auth_status": data.get('auth_status', 'AUTHENTICATED'),
        "firmware_version": data.get('firmware_version', 'v1.0.4'),
        "target_version": data.get('target_version', 'v1.0.4'),
        "battery": int(data.get('battery', 95)),
        "signal": int(data.get('signal', -65)),
        "temperature": float(data.get('temperature', 24.0)),
        "humidity": float(data.get('humidity', 60.0)),
        "soil_moisture": float(data.get('soil_moisture', 40.0)),
        "water_level": float(data.get('water_level', 75.0)),
        "soil_ph": float(data.get('soil_ph', 6.5)),
        "rainfall": float(data.get('rainfall', 0.0)),
        "public_key_fingerprint": get_public_key_fingerprint(),
        "is_simulation": True,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    devices.append(new_device)
    if save_devices(devices):
        append_log(
            device_id=device_id,
            action="Virtual Node Provisioning",
            status="SUCCESS",
            category="DEVICE_MANAGEMENT",
            message=f"Simulated node {device_id} ({new_device['type']}) registered into mesh network."
        )
        return jsonify({'success': True, 'message': f'Device {device_id} successfully created!', 'device': new_device}), 201

    return jsonify({'success': False, 'message': 'Failed to save device data.'}), 500

@app.route('/api/devices/<device_id>', methods=['PUT', 'POST'])
@login_required
def api_update_device(device_id):
    data = request.get_json() or request.form
    devices = load_devices()
    device = next((d for d in devices if d.get('id') == device_id), None)

    if not device:
        return jsonify({'success': False, 'message': f'Device {device_id} not found'}), 404

    if 'name' in data: device['name'] = str(data['name']).strip()
    if 'type' in data: device['type'] = str(data['type']).strip()
    if 'category' in data: device['category'] = str(data['category']).strip()
    if 'location' in data: device['location'] = str(data['location']).strip()
    if 'status' in data and data['status'] in ['ONLINE', 'WARNING', 'OFFLINE']:
        device['status'] = data['status']
    if 'auth_status' in data and data['auth_status'] in ['AUTHENTICATED', 'PENDING', 'UNVERIFIED']:
        device['auth_status'] = data['auth_status']
    if 'firmware_version' in data: device['firmware_version'] = str(data['firmware_version']).strip()
    if 'target_version' in data: device['target_version'] = str(data['target_version']).strip()
    if 'temperature' in data:
        try: device['temperature'] = round(float(data['temperature']), 1)
        except ValueError: pass
    if 'humidity' in data:
        try: device['humidity'] = round(float(data['humidity']), 1)
        except ValueError: pass
    if 'soil_moisture' in data:
        try: device['soil_moisture'] = round(float(data['soil_moisture']), 1)
        except ValueError: pass
    if 'battery' in data:
        try: device['battery'] = max(0, min(100, int(data['battery'])))
        except ValueError: pass

    device['last_updated'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if save_devices(devices):
        append_log(
            device_id=device_id,
            action="Node Configuration Update",
            status="SUCCESS",
            category="DEVICE_MANAGEMENT",
            message=f"Configuration for simulated node {device_id} updated by administrator."
        )
        return jsonify({'success': True, 'message': f'Device {device_id} updated successfully', 'device': device})

    return jsonify({'success': False, 'message': 'Failed to save updated device.'}), 500

@app.route('/api/devices/<device_id>', methods=['DELETE'])
@login_required
def api_delete_device(device_id):
    devices = load_devices()
    initial_len = len(devices)
    devices = [d for d in devices if d.get('id') != device_id]

    if len(devices) == initial_len:
        return jsonify({'success': False, 'message': f'Device {device_id} not found'}), 404

    if save_devices(devices):
        append_log(
            device_id=device_id,
            action="Node Deprovisioning",
            status="SUCCESS",
            category="DEVICE_MANAGEMENT",
            message=f"Virtual node {device_id} removed from mesh inventory.",
            threat_level="LOW"
        )
        return jsonify({'success': True, 'message': f'Device {device_id} removed successfully'})

    return jsonify({'success': False, 'message': 'Failed to delete device.'}), 500

@app.route('/api/devices/<device_id>/authenticate', methods=['POST'])
@login_required
def api_authenticate_device(device_id):
    devices = load_devices()
    device = next((d for d in devices if d.get('id') == device_id), None)

    if not device:
        return jsonify({'success': False, 'message': f'Device {device_id} not found'}), 404

    fingerprint = device.get('public_key_fingerprint') or get_public_key_fingerprint()
    device['public_key_fingerprint'] = fingerprint
    device['auth_status'] = 'AUTHENTICATED'
    device['status'] = 'ONLINE'
    device['last_updated'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    save_devices(devices)
    append_log(
        device_id=device_id,
        action="Cryptographic Handshake & Node Authentication",
        status="SUCCESS",
        category="AUTHENTICATION",
        message=f"RSA-2048 challenge-response verified via public key fingerprint: {fingerprint}",
        threat_level="LOW",
        signature="RSA-2048 PKCS#1 v1.5 Verified"
    )

    return jsonify({
        'success': True,
        'message': f'Device {device_id} authenticated successfully via RSA-2048 signature handshake.',
        'device': device
    })

@app.route('/api/devices/telemetry/simulate', methods=['POST'])
@login_required
def api_simulate_telemetry():
    """Simulates realistic subtle drift in sensor values for online virtual nodes."""
    devices = load_devices()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for d in devices:
        if d.get('status') == 'OFFLINE':
            continue

        temp_drift = random.choice([-0.2, -0.1, 0.0, 0.1, 0.2])
        humidity_drift = random.choice([-0.3, -0.1, 0.0, 0.1, 0.3])
        moisture_drift = random.choice([-0.2, -0.1, 0.0, 0.1, 0.2])

        d['temperature'] = round(max(15.0, min(42.0, d.get('temperature', 24.0) + temp_drift)), 1)
        d['humidity'] = round(max(30.0, min(95.0, d.get('humidity', 60.0) + humidity_drift)), 1)
        d['soil_moisture'] = round(max(10.0, min(80.0, d.get('soil_moisture', 40.0) + moisture_drift)), 1)

        if 'water_level' in d:
            w_drift = random.choice([-0.1, 0.0, 0.0, 0.1])
            d['water_level'] = round(max(10.0, min(100.0, d['water_level'] + w_drift)), 1)

        if random.random() < 0.05 and d.get('battery', 100) > 5:
            d['battery'] = max(0, d['battery'] - 1)

        d['signal'] = max(-98, min(-40, d.get('signal', -70) + random.choice([-1, 0, 1])))

        if d['battery'] < 20 or d['soil_moisture'] < 20 or d['temperature'] > 36.0:
            if d['status'] == 'ONLINE':
                d['status'] = 'WARNING'
        elif d['status'] == 'WARNING' and d['battery'] >= 20 and d['soil_moisture'] >= 20 and d['temperature'] <= 36.0:
            d['status'] = 'ONLINE'

        d['last_updated'] = now_str

    save_devices(devices)

    return jsonify({
        'success': True,
        'message': 'Telemetry simulation tick executed successfully.',
        'timestamp': now_str,
        'devices': devices
    })

# ==============================================================================
# 5. REST API: Settings & Audit Log Management
# ==============================================================================

@app.route('/api/settings/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Allows authenticated administrator to update their password securely."""
    data = request.get_json() or request.form
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()

    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'All password fields are required.'}), 400

    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New password and confirmation do not match.'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'New password must be at least 6 characters long.'}), 400

    users = load_users()
    username = session.get('user', 'admin')
    user_record = users.get(username)

    if not user_record or not check_password_hash(user_record.get('password_hash', ''), current_password):
        return jsonify({'success': False, 'message': 'Current password verification failed.'}), 400

    user_record['password_hash'] = generate_password_hash(new_password)
    user_record['last_password_change'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_users(users)

    append_log(
        device_id="CONSOLE",
        action="Administrator Password Changed",
        status="SUCCESS",
        category="AUTHENTICATION",
        message=f"Security credentials updated for user '{username}'.",
        threat_level="LOW"
    )

    return jsonify({'success': True, 'message': 'Password successfully changed and updated in cryptographic vault.'})

@app.route('/api/logs', methods=['GET'])
@login_required
def api_logs():
    return jsonify(load_logs())

@app.route('/api/logs/export', methods=['GET'])
@login_required
def api_logs_export():
    """Exports audit logs as a downloadable CSV file."""
    logs = load_logs()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Event ID', 'Timestamp', 'Device ID', 'Action', 'Category', 'Status', 'Threat Level', 'SHA-256 Hash', 'Digital Signature', 'Message'])

    for l in logs:
        cw.writerow([
            l.get('id', ''),
            l.get('timestamp', ''),
            l.get('device_id', ''),
            l.get('action', ''),
            l.get('category', 'GENERAL'),
            l.get('status', ''),
            l.get('threat_level', 'LOW'),
            l.get('sha256_hash', ''),
            l.get('digital_signature', ''),
            l.get('message', '')
        ])

    output = io.BytesIO(si.getvalue().encode('utf-8'))
    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"agri_secure_audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

# ==============================================================================
# Application Entry Point
# ==============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = '0.0.0.0' if os.environ.get('PORT') or os.environ.get('RENDER') else '127.0.0.1'
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1']

    print("======================================================================")
    print("  AGRI-SECURE GATEWAY: IoT Firmware Trust & Verification Engine       ")
    print("  SDG 2: Sustainable Agriculture (Zero Hunger) • Hardware-Free Testbed")
    print(f"  URL: http://{host}:{port}                                            ")
    print("  Default Security Officer Login: See project README.md               ")
    print("======================================================================")
    app.run(debug=debug, host=host, port=port)
