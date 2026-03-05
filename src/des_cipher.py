import secrets
from Crypto.Cipher import DES
from utils import pkcs7_pad, pkcs7_unpad


def generate_des_key():
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).
    """
    key = secrets.token_bytes(8)
    print("Clave DES:", key.hex())
    return key


def generate_3des_key(key_option=2):
    """
    Genera una clave 3DES aleatoria.
    """
    if key_option == 2:
        size = 16
    elif key_option == 3:
        size = 24
    else:
        raise ValueError("Solo se permite 2 o 3 como opción.")

    key = secrets.token_bytes(size)
    print("Clave 3DES:", key.hex())
    return key


def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.
    """
    if key_size not in [128, 192, 256]:
        raise ValueError("Tamaño inválido para AES")

    size = key_size // 8
    key = secrets.token_bytes(size)
    print("Clave AES:", key.hex())
    return key



def generate_iv(block_size: int = 8):
    """
    Genera un vector de inicialización (IV) aleatorio.
    """
    iv = secrets.token_bytes(block_size)
    print("IV:", iv.hex())
    return iv

# Cifrado DES - Modo ECB

def encrypt_des_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra un mensaje usando DES en modo ECB.

    Args:
        plaintext: Mensaje en bytes a cifrar.
        key: Clave DES de 8 bytes.

    Returns:
        Texto cifrado en bytes.
    """
    if len(key) != 8:
        raise ValueError("La clave DES debe ser exactamente 8 bytes.")

    padded = pkcs7_pad(plaintext, block_size=DES.block_size)
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(padded)

    print(f"Texto cifrado (hex): {ciphertext.hex()}")
    return ciphertext


def decrypt_des_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra un mensaje usando DES en modo ECB.
    """
    if len(key) != 8:
        raise ValueError("La clave DES debe ser exactamente 8 bytes.")

    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(padded_plaintext, block_size=DES.block_size)

    print(f"Texto descifrado: {plaintext}")
    return plaintext
