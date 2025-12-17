from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import hashlib

class FileEncryption:
    def __init__(self, key):
        """Initialize with a 32-byte encryption key"""
        if len(key) != 32:
            self.key = hashlib.sha256(key.encode() if isinstance(key, str) else key).digest()
        else:
            self.key = key
    
    def encrypt_file(self, file_data):
        """
        Encrypt file data using AES-256 in CBC mode
        Returns: (encrypted_data, iv)
        """
        iv = os.urandom(16)
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        padded_data = self._pad(file_data)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data, iv
    
    def decrypt_file(self, encrypted_data, iv):
        """
        Decrypt file data using AES-256 in CBC mode
        Returns: original file data
        """
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        original_data = self._unpad(padded_data)
        
        return original_data
    
    def _pad(self, data):
        """Add PKCS7 padding"""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad(self, padded_data):
        """Remove PKCS7 padding"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    @staticmethod
    def compute_hash(data):
        """Compute SHA-256 hash of data for integrity verification"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def verify_hash(data, expected_hash):
        """Verify data integrity using hash"""
        computed_hash = FileEncryption.compute_hash(data)
        return computed_hash == expected_hash