import json
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1, SHA256

# AES Functions
def generate_aes_key():
    return get_random_bytes(16)

def pad(data):
    padding_len = AES.block_size - len(data) % AES.block_size
    padding = bytes([padding_len]) * padding_len
    return data + padding

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def encrypt_file_aes(file_path, key, mode='EAX'):
    with open(file_path, 'rb') as f:
        data = f.read()
    if mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(data))
        return ciphertext, cipher.iv, None
    elif mode == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB)
        ciphertext = cipher.encrypt(data)
        return ciphertext, cipher.iv, None
    elif mode == 'CTR':
        cipher = AES.new(key, AES.MODE_CTR)
        ciphertext = cipher.encrypt(data)
        return ciphertext, cipher.nonce, None
    elif mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data))
        return ciphertext, None, None
    else:  # Default to EAX
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, cipher.nonce, tag

def decrypt_file_aes(ciphertext, key, mode, nonce_or_iv=None, tag=None):
    if mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv=nonce_or_iv)
        data = unpad(cipher.decrypt(ciphertext))
    elif mode == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB, iv=nonce_or_iv)
        data = cipher.decrypt(ciphertext)
    elif mode == 'CTR':
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce_or_iv)
        data = cipher.decrypt(ciphertext)
    elif mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        data = unpad(cipher.decrypt(ciphertext))
    else:  # EAX
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce_or_iv)
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
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = SHA1.new()
    h.update(data)
    return h.hexdigest()

def calculate_sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()
