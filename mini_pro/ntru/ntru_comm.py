import base64
import numpy as np
from NTRUencrypt import NTRUencrypt
from NTRUdecrypt import NTRUdecrypt

# Encrypt using the public key
def encrypt_message(message, pub_key_path="key.pub"):
    enc = NTRUencrypt()
    enc.readPub(pub_key_path)
    enc.encryptString(message)
    encrypted_str = enc.Me.strip()
    encrypted_bytes = encrypted_str.encode()
    return base64.b64encode(encrypted_bytes)

# Decrypt using the private key
def decrypt_message(encrypted_b64, priv_key_path="key.priv"):
    encrypted_str = base64.b64decode(encrypted_b64).decode()
    dec = NTRUdecrypt()
    dec.readPriv(priv_key_path)
    dec.decryptString(encrypted_str)
    return dec.M

# Aliases for clarity 
encrypt_for_cloud = encrypt_message
encrypt_for_fog = encrypt_message
encrypt_for_edge=encrypt_message
decrypt_from_fog = decrypt_message
decrypt_from_cloud = decrypt_message
decrypt_from_edge=decrypt_message