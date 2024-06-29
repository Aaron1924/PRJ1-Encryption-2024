import json
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1, SHA256

# AES Functions
def generate_aes_key():
    return get_random_bytes(16)

def encrypt_file_aes(file_path, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag

def decrypt_file_aes(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

# RSA Functions
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

def encrypt_string_rsa(plaintext, public_key):
    recipient_key = RSA.import_key(public_key.encode('utf-8'))
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted = cipher_rsa.encrypt(plaintext)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_string_rsa(ciphertext, private_key):
    private_key = RSA.import_key(private_key.encode('utf-8'))
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted = cipher_rsa.decrypt(base64.b64decode(ciphertext.encode('utf-8')))
    return decrypted

# Hash Functions
def calculate_sha1(data):
    h = SHA1.new()
    h.update(data.encode('utf-8'))
    return h.hexdigest()

def calculate_sha256(data):
    h = SHA256.new()
    h.update(data.encode('utf-8'))
    return h.hexdigest()

