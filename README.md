# AGRI-SECURE GATEWAY
### Secure IoT Firmware Update System Using Digital Signatures for Sustainable Agriculture (SDG 2)

A comprehensive, software-based cybersecurity platform designed to protect smart agricultural IoT infrastructure against firmware poisoning, unauthorized binary tampering, and cyber-physical disruption. Aligned with **United Nations Sustainable Development Goal 2 (SDG 2: Zero Hunger)**.

> **Hardware Notice**: This is a 100% software-based cybersecurity testbed. All 10 agricultural sensors, field nodes, and microcontrollers are simulated programmatically in Python and JavaScript. **No physical hardware, Arduino, ESP32, or physical sensors are required.**

---

## 1. System Architecture & Cryptographic Stack

- **Backend Framework**: Python 3 / Flask
- **Cryptographic Engine**: Python `cryptography`
  - **RSA-2048**: Asymmetric digital signatures (PKCS#1 v1.5 with SHA-256) for vendor firmware origin authentication and non-repudiation.
  - **SHA-256**: Cryptographic digest calculation for binary integrity verification and avalanche effect visualization.
  - **AES-256-GCM**: Authenticated Symmetric Encryption (Galois/Counter Mode with 96-bit nonce and 128-bit authentication tag) for firmware confidentiality and tamper detection.
- **Data Persistence**: JSON database storage (`data/devices.json`, `data/users.json`, `data/update_logs.json`).
- **Frontend Technologies**: HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons, Chart.js 4.4, Canvas Network Particle Engine, and Jinja2 templates.
- **Visual Design**: High-contrast Cyber Security Operations Center (SOC) theme featuring Dark Navy (`#030712`, `#070d1d`), Obsidian Black, and Cyber Neon-Green (`#00ff9d`, `#10b981`) highlights with glassmorphism cards.

---

## 2. Evaluation Credentials

For evaluation, academic grading, and testing:

| Role | Username | Password | Storage Scheme |
| :--- | :--- | :--- | :--- |
| **Security Officer** | `admin` | `admin123` | Scrypt / PBKDF2 Password Hashing (`data/users.json`) |

*Security Notice: Hardcoded credentials have been removed from all frontend templates and are verified via password hashing. Private cryptographic keys (`keys/vendor_private_key.pem`) are strictly isolated on the backend server with 0600 file permissions and never exposed to client browsers.*

---

## 3. Dedicated Module Pages & Navigation

The platform organizes every major capability into separate, dedicated pages with unified navigation:

| Module Page | Route | Description |
| :--- | :--- | :--- |
| **1. SOC Dashboard** | `/dashboard` | High-level summary metrics, fleet distribution charts, recent security events, and SDG 2 impact overview. |
| **2. Virtual IoT Devices** | `/devices` | Complete fleet management for 10 virtual agricultural nodes with live telemetry, status filters, and CRUD modals. |
| **3. RSA Signatures** | `/rsa-signatures` | Asymmetric RSA-2048 signing studio, signature verification, and 1-click tampering attack simulation. |
| **4. SHA-256 Integrity** | `/sha256-integrity` | Cryptographic digest generator, dual-hash comparator, and live avalanche effect demonstration. |
| **5. AES-256 Encryption** | `/aes256-encryption` | Authenticated AES-256-GCM studio with 96-bit nonce, 128-bit authentication tag, and ciphertext tampering rejection. |
| **6. Secure OTA Updates** | `/ota-updates` | Multi-stage Over-The-Air deployment pipeline, node selector, valid vs. attack simulation, and live bootloader terminal console. |
| **7. Audit Logs** | `/audit-logs` | Real-time searchable security events table with category/threat filters and CSV export. |
| **8. Security Settings** | `/settings` | Officer profile, secure password change, asymmetric key vault inspection, and 1-click RSA keypair rotation. |

---

## 4. How to Run on macOS

### Prerequisites
- macOS terminal (zsh or bash).
- Python 3.10+ installed.

### Step-by-Step Instructions

1. **Open Terminal** and enter the project directory:
   ```bash
   cd /Users/lohithnarra/Secure_IoT_Firmware_System
   ```

2. **Activate the Virtual Environment**:
   ```bash
   source venv/bin/activate
   ```

3. **Verify Dependencies** (if needed):
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Automated Test Suite**:
   ```bash
   python3 -m unittest -v test_suite.py
   ```
   *All 8 tests (authentication, page routing, device CRUD, telemetry drift, RSA, SHA-256, AES-256-GCM, and OTA attack rejection) will pass with `OK`.*

5. **Start the Flask Application**:
   ```bash
   python3 app.py
   ```

6. **Open in Web Browser**:
   - Navigate to: **`http://127.0.0.1:5000`**
   - Sign in using `admin` / `admin123`.

---

## 5. Virtual IoT Device Fleet (10 Nodes)

| Node ID | Node Name | Category | Primary Telemetry |
| :--- | :--- | :--- | :--- |
| `AGRI-NODE-01` | Alpha Soil Moisture Station | Soil Moisture Sensor | Soil Moisture: 44.5%, Temp: 23.4°C, Humidity: 62% |
| `AGRI-NODE-02` | Smart Irrigation Controller A | Smart Irrigation Controller | Soil Moisture: 38.0%, Water Level: 76.5% |
| `AGRI-NODE-03` | Sector Canopy Temp Monitor | Temperature Sensor | Temp: 28.5°C, Humidity: 55% |
| `AGRI-NODE-04` | Precision Humidity Node | Humidity Sensor | Humidity: 68.2%, Temp: 22.8°C |
| `AGRI-NODE-05` | Main Reservoir Water Level Probe | Water Level Sensor | Water Level: 84.0%, Battery: 94% |
| `AGRI-NODE-06` | Rootzone Soil pH Analyzer | Soil pH Sensor | Soil pH: 6.7, Soil Moisture: 41.0% |
| `AGRI-NODE-07` | Precipitation & Rainfall Sensor | Rainfall Sensor | Rainfall: 12.4mm, Humidity: 88% |
| `AGRI-NODE-08` | Multispectral Crop Health Node | Crop Monitoring Node | NDVI Index: 0.78, Temp: 24.1°C |
| `AGRI-NODE-09` | Micro-Climate Weather Station | Weather Monitoring Node | Ambient Temp: 21.9°C, Wind: 14 km/h |
| `AGRI-NODE-10` | Agricultural Field Mesh Gateway | Agricultural Gateway | Connected Nodes: 9, Signal: -58 dBm |

---

## 7. Cloud Deployment on Render via GitHub

This project is fully configured for production deployment on [Render](https://render.com) using **Gunicorn** and **Render Blueprints**.

### Production Configuration Files Included:
- **`Procfile`**: Defines the WSGI server command (`web: gunicorn app:app --workers 2 --threads 2 --timeout 60`).
- **`render.yaml`**: Infrastructure-as-code blueprint for 1-click deployment on Render.
- **`runtime.txt`**: Specifies standard Python runtime (`python-3.11.9`).
- **`.env.example`**: Complete template for production environment variables.
- **`.gitignore`**: Strictly isolates private RSA keys, AES master key, and password databases.

### Recommended Render Environment Variables:
| Variable Name | Required | Default / Description |
| :--- | :---: | :--- |
| `PYTHON_VERSION` | Yes | `3.11.9` |
| `FLASK_SECRET_KEY` | Yes | Secure random string for session tokens (auto-generated by Render) |
| `ADMIN_USERNAME` | No | `admin` (Security Officer ID) |
| `ADMIN_PASSWORD` | No | Custom password for production login (defaults to `admin123`) |
| `RSA_PRIVATE_KEY_PEM` | Optional | Set to maintain persistent keypair across Free Tier restarts |
| `RSA_PUBLIC_KEY_PEM` | Optional | Corresponding public key in PEM format |
| `AES_SECRET_KEY_HEX` | Optional | 64-character hexadecimal 256-bit AES master key |

---

## 8. Academic Project Alignment (SDG 2 & Cybersecurity)

- **UN SDG 2 (Zero Hunger)**: Securing automated precision agriculture infrastructure against cyber-attacks, firmware tampering, and malicious logic bombs that could disrupt food production, irrigation systems, or fertilizer distribution.
- **Defense in Depth**: Combines RSA-2048 non-repudiation, SHA-256 integrity, AES-256-GCM authenticated encryption, and tamper-resistant bootloader verification to prevent unauthorized code execution on IoT microcontrollers.

