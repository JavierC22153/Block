import secrets
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from des_cipher import generate_aes_key, generate_iv



# Cifrado AES - Modo ECB
def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra datos usando AES en modo ECB.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("La clave AES debe ser de 16, 24 o 32 bytes.")

    padded = pad(plaintext, AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padded)


def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra datos usando AES en modo ECB.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("La clave AES debe ser de 16, 24 o 32 bytes.")

    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(padded_plaintext, AES.block_size)

# Cifrado AES - Modo CBC
def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Cifra datos usando AES en modo CBC.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("La clave AES debe ser de 16, 24 o 32 bytes.")
    if len(iv) != 16:
        raise ValueError("El IV debe ser de 16 bytes para AES.")

    padded = pad(plaintext, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(padded)


def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Descifra datos usando AES en modo CBC.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("La clave AES debe ser de 16, 24 o 32 bytes.")
    if len(iv) != 16:
        raise ValueError("El IV debe ser de 16 bytes para AES.")

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(padded_plaintext, AES.block_size)


# Procesamiento de imágenes
def process_image(image_path: str) -> tuple[dict, bytes]:
    """
    Separa el header y los datos de píxeles de una imagen.
    """
    with Image.open(image_path) as img:
        if img.mode != 'RGB':
            img = img.convert('RGB')

        pixel_data = img.tobytes()
        header_info = {
            'mode': img.mode,
            'size': img.size
        }
        return header_info, pixel_data


def rebuild_image(header_info: dict, pixel_data: bytes, output_path: str) -> None:
    """
    Reconstruye una imagen a partir del header original y
    los datos de píxeles (cifrados o no).
    """
    expected_size = header_info['size'][0] * header_info['size'][1] * 3
    pixel_data = pixel_data[:expected_size]

    img = Image.frombytes(header_info['mode'], header_info['size'], pixel_data)
    img.save(output_path)
    print(f"Imagen guardada en: {output_path}")


def encrypt_image_ecb(input_path: str, output_path: str, key: bytes) -> None:
    """
    Cifra los píxeles de una imagen usando AES-ECB.
    El header (modo y tamaño) se mantiene intacto.
    """
    header_info, pixel_data = process_image(input_path)
    encrypted_pixels = encrypt_aes_ecb(pixel_data, key)
    rebuild_image(header_info, encrypted_pixels, output_path)
    print(f"[ECB] Imagen cifrada guardada en: {output_path}")


def encrypt_image_cbc(input_path: str, output_path: str, key: bytes, iv: bytes) -> None:
    """
    Cifra los píxeles de una imagen usando AES-CBC.
    El IV aleatorio garantiza que el cifrado sea distinto cada vez.
    """
    header_info, pixel_data = process_image(input_path)
    encrypted_pixels = encrypt_aes_cbc(pixel_data, key, iv)
    rebuild_image(header_info, encrypted_pixels, output_path)
    print(f"[CBC] Imagen cifrada guardada en: {output_path}")