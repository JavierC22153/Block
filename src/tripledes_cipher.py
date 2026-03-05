from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from des_cipher import generate_3des_key, generate_iv


def encrypt_3des_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Cifra un mensaje usando Triple DES (3DES) en modo CBC.

    """
    if len(key) not in (16, 24):
        raise ValueError("La clave debe ser de 16 o 24 bytes")
    if len(iv) != 8:
        raise ValueError("El IV debe ser de 8 bytes para 3DES")
    
    padded_plaintext = pad(plaintext, DES3.block_size)
    
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    
    return cipher.encrypt(padded_plaintext)


def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Descifra un mensaje usando Triple DES (3DES) en modo CBC.
    
    """
    if len(key) not in (16, 24):
        raise ValueError("La clave debe ser de 16 o 24 bytes")
    if len(iv) != 8:
        raise ValueError("El IV debe ser de 8 bytes para 3DES")
    
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    
    padded_plaintext = cipher.decrypt(ciphertext)
    
    plaintext = unpad(padded_plaintext, DES3.block_size)

    return plaintext