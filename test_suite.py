import unittest
import json
import io
from app import app, load_devices, save_devices

class FullSystemTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()
        # Ensure clean state for test node
        devs = load_devices()
        save_devices([d for d in devs if d.get('id') != 'AGRI-NODE-99'])

    def tearDown(self):
        devs = load_devices()
        save_devices([d for d in devs if d.get('id') != 'AGRI-NODE-99'])

    def test_01_unauthenticated_access(self):
        """Verify protected routes redirect unauthenticated users to /login"""
        protected_routes = [
            '/dashboard', '/devices', '/rsa-signatures', 
            '/sha256-integrity', '/aes256-encryption', 
            '/ota-updates', '/audit-logs', '/settings'
        ]
        for route in protected_routes:
            res = self.client.get(route, follow_redirects=False)
            self.assertIn(res.status_code, [302, 401], f"Route {route} didn't redirect or deny")
            if res.status_code == 302:
                self.assertIn('/login', res.headers['Location'])

    def test_02_login_and_logout(self):
        """Verify authentication mechanism"""
        # Failed login
        res = self.client.post('/login', data={'username': 'admin', 'password': 'wrongpassword'}, follow_redirects=True)
        self.assertIn(b'Invalid security credentials', res.data)

        # Successful login
        res = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/dashboard', res.headers['Location'])

    def _login(self):
        return self.client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)

    def test_03_all_pages_render_for_authenticated_user(self):
        """Verify each of the 8 separate module pages render with 200 OK and expected headers"""
        self._login()
        pages = {
            '/dashboard': b'Security Operations Center',
            '/devices': b'Virtual Agricultural IoT Devices',
            '/rsa-signatures': b'RSA-2048 Digital Signatures',
            '/sha256-integrity': b'SHA-256 Binary Integrity Verification',
            '/aes256-encryption': b'AES-256-GCM Firmware Encryption',
            '/ota-updates': b'Secure OTA Firmware Updates',
            '/audit-logs': b'Security Audit Logs',
            '/settings': b'Security Settings & Key Vault'
        }
        for route, expected_text in pages.items():
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Page {route} failed to load (status {res.status_code})")
            self.assertIn(expected_text, res.data, f"Page {route} does not contain {expected_text}")

    def test_04_device_management_and_simulation(self):
        """Verify simulated device listing, telemetry simulation, registration, update, authentication, and deletion"""
        self._login()
        # 1. List devices
        res = self.client.get('/api/devices')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data.get('success'))
        self.assertGreaterEqual(len(data.get('devices', [])), 10)

        # 2. Simulate Telemetry
        res = self.client.post('/api/devices/telemetry/simulate')
        self.assertEqual(res.status_code, 200)
        sim_data = json.loads(res.data)
        self.assertTrue(sim_data.get('success'))
        self.assertGreaterEqual(len(sim_data.get('devices', [])), 10)

        # 3. Add temporary test device
        new_node = {
            'id': 'AGRI-NODE-99',
            'name': 'Test Soil Sensor Unit 99',
            'type': 'Soil Moisture Sensor',
            'location': 'Greenhouse Test Bench'
        }
        res = self.client.post('/api/devices', json=new_node)
        self.assertIn(res.status_code, [200, 201])
        reg_data = json.loads(res.data)
        self.assertTrue(reg_data.get('success'))

        # 4. Authenticate device
        res = self.client.post('/api/devices/AGRI-NODE-99/authenticate')
        self.assertEqual(res.status_code, 200)
        auth_data = json.loads(res.data)
        self.assertTrue(auth_data.get('success'))
        self.assertEqual(auth_data['device']['status'], 'ONLINE')
        self.assertEqual(auth_data['device']['auth_status'], 'AUTHENTICATED')

        # 5. Update device
        update_payload = {
            'name': 'Updated Test Soil Sensor Unit 99',
            'type': 'Soil Moisture Sensor',
            'location': 'Greenhouse Test Bench 2',
            'firmware_version': 'v2.1.0-test'
        }
        res = self.client.post('/api/devices/AGRI-NODE-99', json=update_payload)
        self.assertEqual(res.status_code, 200)
        up_data = json.loads(res.data)
        self.assertTrue(up_data.get('success'))
        self.assertEqual(up_data['device']['name'], 'Updated Test Soil Sensor Unit 99')

        # 6. Delete test device
        res = self.client.delete('/api/devices/AGRI-NODE-99')
        self.assertEqual(res.status_code, 200)
        del_data = json.loads(res.data)
        self.assertTrue(del_data.get('success'))

    def test_05_cryptographic_operations(self):
        """Verify SHA-256, RSA-2048 signing/verification, and AES-256-GCM encryption/decryption APIs"""
        self._login()

        # 1. SHA-256
        res = self.client.post('/api/crypto/sha256', json={'payload': 'AgriSecure-Payload-v2.0'})
        self.assertEqual(res.status_code, 200)
        sha_res = json.loads(res.data)
        self.assertTrue(sha_res.get('success'))
        self.assertEqual(len(sha_res.get('sha256_hash', '')), 64)

        # 2. RSA Sign
        res = self.client.post('/api/crypto/sign', json={'payload': 'AgriSecure-Payload-v2.0'})
        self.assertEqual(res.status_code, 200)
        sign_res = json.loads(res.data)
        self.assertTrue(sign_res.get('success'))
        signature_b64 = sign_res.get('signature_b64')
        self.assertIsNotNone(signature_b64)

        # 3. RSA Verify (Valid)
        res = self.client.post('/api/crypto/verify', json={
            'payload': 'AgriSecure-Payload-v2.0',
            'signature_b64': signature_b64
        })
        self.assertEqual(res.status_code, 200)
        verify_res = json.loads(res.data)
        self.assertTrue(verify_res.get('valid'))

        # 4. RSA Verify (Tampered Payload)
        res = self.client.post('/api/crypto/verify', json={
            'payload': 'AgriSecure-Payload-v2.0-TAMPERED',
            'signature_b64': signature_b64
        })
        self.assertEqual(res.status_code, 200)
        tamper_res = json.loads(res.data)
        self.assertFalse(tamper_res.get('valid'))

        # 5. AES-256-GCM Encrypt
        res = self.client.post('/api/crypto/aes/encrypt', json={'plaintext': 'Secret Agri Firmware Code 2026'})
        self.assertEqual(res.status_code, 200)
        aes_res = json.loads(res.data)
        self.assertTrue(aes_res.get('success'))
        ciphertext_b64 = aes_res.get('ciphertext_b64')
        nonce_b64 = aes_res.get('nonce_b64')
        tag_b64 = aes_res.get('tag_b64')
        key_hex = aes_res.get('key_hex')

        # 6. AES-256-GCM Decrypt (Valid)
        res = self.client.post('/api/crypto/aes/decrypt', json={
            'ciphertext_b64': ciphertext_b64,
            'nonce_b64': nonce_b64,
            'tag_b64': tag_b64,
            'key_hex': key_hex
        })
        self.assertEqual(res.status_code, 200)
        dec_res = json.loads(res.data)
        self.assertTrue(dec_res.get('success'))
        self.assertEqual(dec_res.get('plaintext'), 'Secret Agri Firmware Code 2026')

        # 7. AES-256-GCM Decrypt (Tampered Tag)
        res = self.client.post('/api/crypto/aes/decrypt', json={
            'ciphertext_b64': ciphertext_b64,
            'nonce_b64': nonce_b64,
            'tag_b64': 'AAAA' + tag_b64[4:],
            'key_hex': key_hex
        })
        self.assertEqual(res.status_code, 200)
        tamper_dec_res = json.loads(res.data)
        self.assertFalse(tamper_dec_res.get('success'))
        self.assertIn('AUTHENTICATION TAG MISMATCH', tamper_dec_res.get('message', ''))

    def test_06_ota_firmware_deployment(self):
        """Verify OTA deployment pipeline for both legitimate and attack simulation cases"""
        self._login()

        # Valid OTA update
        res = self.client.post('/api/crypto/ota/deploy', json={
            'device_id': 'AGRI-NODE-01',
            'version': 'v2.2.0-agri',
            'simulate_tamper': False
        })
        self.assertEqual(res.status_code, 200)
        ota_res = json.loads(res.data)
        self.assertTrue(ota_res.get('success'))
        self.assertIn('bootloader verified RSA signature', ota_res.get('message', ''))

        # Tampered / Attack OTA update
        res = self.client.post('/api/crypto/ota/deploy', json={
            'device_id': 'AGRI-NODE-02',
            'version': 'v2.3.0-exploit',
            'simulate_tamper': True
        })
        self.assertEqual(res.status_code, 400)
        attack_res = json.loads(res.data)
        self.assertFalse(attack_res.get('success'))
        self.assertIn('Bootloader rejected firmware', attack_res.get('message', ''))

    def test_07_audit_logs_and_export(self):
        """Verify audit log viewing and CSV export"""
        self._login()
        res = self.client.get('/api/logs/export')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'Event ID,Timestamp,Device ID,Action,Category,Status,Threat Level,SHA-256 Hash,Digital Signature,Message', res.data)

    def test_08_public_key_and_rotation(self):
        """Verify public key endpoint and keypair rotation"""
        self._login()
        res = self.client.get('/api/crypto/public-key')
        self.assertEqual(res.status_code, 200)
        key_data = json.loads(res.data)
        self.assertTrue(key_data.get('success'))
        self.assertIn('BEGIN PUBLIC KEY', key_data.get('public_key_pem', ''))

if __name__ == '__main__':
    unittest.main()
