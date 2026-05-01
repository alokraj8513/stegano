import cv2
import numpy as np
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


# ==========================================
# CRYPTOGRAPHIC ENGINE
# ==========================================

def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derives a strong key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())


# --- AES-256-GCM ---
def encrypt_aes(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return base64.b64encode(salt + nonce + ciphertext).decode('utf-8')


def decrypt_aes(encrypted_msg: str, password: str) -> str:
    data = base64.b64decode(encrypted_msg)
    salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')


# --- ChaCha20-Poly1305 ---
def encrypt_chacha(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, message.encode(), None)
    return base64.b64encode(salt + nonce + ciphertext).decode('utf-8')


def decrypt_chacha(encrypted_msg: str, password: str) -> str:
    data = base64.b64decode(encrypted_msg)
    salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
    key = derive_key(password, salt)
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None).decode('utf-8')


# --- Fernet ---
def encrypt_fernet(message: str, password: str) -> str:
    salt = os.urandom(16)
    # Fernet requires a 32-byte url-safe base64 encoded key
    key = base64.urlsafe_b64encode(derive_key(password, salt))
    f = Fernet(key)
    ciphertext = f.encrypt(message.encode())
    return base64.b64encode(salt + ciphertext).decode('utf-8')


def decrypt_fernet(encrypted_msg: str, password: str) -> str:
    data = base64.b64decode(encrypted_msg)
    salt, ciphertext = data[:16], data[16:]
    key = base64.urlsafe_b64encode(derive_key(password, salt))
    f = Fernet(key)
    return f.decrypt(ciphertext).decode('utf-8')


# --- Legacy XOR ---
def encrypt_xor(message: str, key: str) -> str:
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(message))


def decrypt_xor(message: str, key: str) -> str:
    return encrypt_xor(message, key)


# ==========================================
# STEGANOGRAPHY CORE (LSB)
# ==========================================

def to_bits(message):
    bits = ''.join(format(ord(c), '08b') for c in message)
    return bits + '1111111111111110'  # 16-bit delimiter


def embed_message(image_path, message, password, algo, output_path):
    if not password:
        raise ValueError("Encryption key cannot be empty.")

    # Route to selected algorithm
    try:
        if algo == "AES-256-GCM":
            encrypted_msg = encrypt_aes(message, password)
        elif algo == "ChaCha20-Poly1305":
            encrypted_msg = encrypt_chacha(message, password)
        elif algo == "Fernet":
            encrypted_msg = encrypt_fernet(message, password)
        else:
            encrypted_msg = encrypt_xor(message, password)
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

    bits = to_bits(encrypted_msg)

    img = cv2.imread(image_path)
    if img is None:
        raise ValueError("Error: Image not found or format unsupported.")

    flat = img.flatten()
    if len(bits) > len(flat):
        raise ValueError("Error: Message too large for this image's capacity.")

    for i in range(len(bits)):
        flat[i] = (flat[i] & 0xFE) | int(bits[i])

    encoded_img = flat.reshape(img.shape)
    cv2.imwrite(output_path, encoded_img)


def extract_message(image_path, password, algo):
    if not password:
        raise ValueError("Decryption key cannot be empty.")

    img = cv2.imread(image_path)
    if img is None:
        raise ValueError("Error: Image not found.")

    bits = ''.join([str(b & 1) for b in img.flatten()])

    bytes_list = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    chars = []
    for b in bytes_list:
        if b == '11111110':
            break
        chars.append(chr(int(b, 2)))

    extracted_data = ''.join(chars)

    # Route to selected algorithm
    try:
        if algo == "AES-256-GCM":
            return decrypt_aes(extracted_data, password)
        elif algo == "ChaCha20-Poly1305":
            return decrypt_chacha(extracted_data, password)
        elif algo == "Fernet":
            return decrypt_fernet(extracted_data, password)
        else:
            return decrypt_xor(extracted_data, password)
    except Exception:
        raise ValueError("Decryption failed. Incorrect password, algorithm, or corrupted data.")


# ==========================================
# FORENSIC ANALYSIS
# ==========================================

def generate_lsb_map(image_path, output_path):
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError("Image not found.")
    lsb_plane = img & 1
    visual_map = lsb_plane * 255
    cv2.imwrite(output_path, visual_map)
    return output_path


def predict_steganography(image_path):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError("Image not found.")
    lsb_plane = img & 1
    h, w = lsb_plane.shape
    top_slice = lsb_plane[0:int(h * 0.1), :]
    density = np.mean(top_slice)
    confidence = abs(density - 0.5) * 200
    is_modified = confidence > 75.0
    return is_modified, min(max(confidence, 0.0), 99.9)