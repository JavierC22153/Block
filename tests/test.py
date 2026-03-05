import sys
import os
from PIL import Image, ImageDraw

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from des_cipher import generate_des_key, generate_3des_key, generate_aes_key, generate_iv
from des_cipher import encrypt_des_ecb
from aes_cipher import encrypt_image_ecb, encrypt_image_cbc, encrypt_aes_ecb, encrypt_aes_cbc
from tripledes_cipher import encrypt_3des_cbc, decrypt_3des_cbc
from utils import pkcs7_pad, pkcs7_unpad


def header(title):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")

# IMÁGENES — AES ECB vs CBC
header("IMÁGENES — AES ECB vs CBC")

BASE_DIR  = os.path.join(os.path.dirname(__file__), '..')
img_input = os.path.join(BASE_DIR, "images", "original.png")
img_ecb   = os.path.join(BASE_DIR, "images", "aes_ecb.png")
img_cbc   = os.path.join(BASE_DIR, "images", "aes_cbc.png")

if not os.path.exists(img_input):
    print("  No se encontro original.png — colócala en images/")
else:
    key_img = generate_aes_key(256)
    iv_img  = generate_iv(block_size=16)

    encrypt_image_ecb(img_input, img_ecb, key_img)
    encrypt_image_cbc(img_input, img_cbc, key_img, iv_img)

    img_comparison = os.path.join(BASE_DIR, "images", "comparison.png")
    orig = Image.open(img_input).convert("RGB")
    ecb  = Image.open(img_ecb).convert("RGB")
    cbc  = Image.open(img_cbc).convert("RGB")

    W, H    = orig.size
    label_h = 40
    pad     = 10
    canvas  = Image.new("RGB", (W*3 + pad*4, H + label_h + pad*2), (30, 30, 30))
    draw    = ImageDraw.Draw(canvas)

    for (x, label), img in zip(
        [(pad, "Original"), (W+pad*2, "AES-ECB"), (W*2+pad*3, "AES-CBC")],
        [orig, ecb, cbc]
    ):
        canvas.paste(img, (x, label_h))
        draw.text((x + W//2, pad), label, fill=(255, 255, 255), anchor="mt")

    canvas.save(img_comparison)
    print(f"  ECB guardada  -> {img_ecb}")
    print(f"  CBC guardada  -> {img_cbc}")
    print(f"  Comparativa   -> {img_comparison}")


# ANÁLISIS 2.1 — Tamaños de clave
header("ANÁLISIS 2.1 — Tamaños de clave")

key_des  = generate_des_key()
key_3des = generate_3des_key(key_option=2)
key_aes  = generate_aes_key(256)

print(f"\n  {'Algoritmo':<10} {'Bytes':>6}   {'Bits':>6}")
print(f"  {'─'*28}")
print(f"  {'DES':<10} {len(key_des):>6}   {len(key_des)*8:>6}")
print(f"  {'3DES':<10} {len(key_3des):>6}   {len(key_3des)*8:>6}")
print(f"  {'AES-256':<10} {len(key_aes):>6}   {len(key_aes)*8:>6}")

print(f"\n  Tiempo de fuerza bruta (GPU ~10^9 claves/seg):\n")
GPU = 1_000_000_000
for name, bits in [("DES", 56), ("3DES", 112), ("AES-256", 256)]:
    years  = (2**bits / 2) / GPU / 60 / 60 / 24 / 365.25
    status = "ROMPIBLE" if years < 1 else ("Vulnerable" if years < 1e10 else "Seguro")
    print(f"  {name:<10} 2^{bits:<4} -> {years:.2e} años  [{status}]")


# ANÁLISIS 2.3 — Vulnerabilidad ECB: bloques idénticos
header("ANÁLISIS 2.3 — Vulnerabilidad ECB: bloques idénticos")

key_vuln = generate_aes_key(256)
iv_vuln  = generate_iv(block_size=16)

BLOCK   = b"ATAQUE ATAQUE !!"
mensaje = BLOCK * 3

print(f"\n  Mensaje : {mensaje.decode()!r}  ({len(mensaje)} bytes, {len(mensaje)//16} bloques de 16B)")
print(f"  Bloque  : {BLOCK.hex()}")

ct_ecb = encrypt_aes_ecb(mensaje, key_vuln)
ct_cbc = encrypt_aes_cbc(mensaje, key_vuln, iv_vuln)

ecb_blocks = [ct_ecb[i:i+16] for i in range(0, 48, 16)]
cbc_blocks = [ct_cbc[i:i+16] for i in range(0, 48, 16)]

print(f"\n  {'Bloque':<8} {'ECB (hex)':<35} {'CBC (hex)':<35} ECB repite?")
print(f"  {'─'*88}")
for i, (e, c) in enumerate(zip(ecb_blocks, cbc_blocks)):
    repite = "SI <- peligro" if i > 0 and e == ecb_blocks[0] else "Ref."
    print(f"  {i+1:<8} {e.hex():<35} {c.hex():<35} {repite}")


# ANÁLISIS 2.4 — Vector de Inicialización (IV)
header("ANÁLISIS 2.4 — Vector de Inicialización (IV)")

key_iv     = generate_aes_key(256)
mensaje_iv = b"Mensaje secreto!"

iv_fijo = generate_iv(block_size=16)
ct_1a   = encrypt_aes_cbc(mensaje_iv, key_iv, iv_fijo)
ct_1b   = encrypt_aes_cbc(mensaje_iv, key_iv, iv_fijo)

print(f"\n  Experimento 1 — Mismo IV: {iv_fijo.hex()}")
print(f"  Cifrado A : {ct_1a.hex()}")
print(f"  Cifrado B : {ct_1b.hex()}")
print(f"  Resultado : {'IDENTICOS' if ct_1a == ct_1b else 'DISTINTOS'}")

iv_a  = generate_iv(block_size=16)
iv_b  = generate_iv(block_size=16)
ct_2a = encrypt_aes_cbc(mensaje_iv, key_iv, iv_a)
ct_2b = encrypt_aes_cbc(mensaje_iv, key_iv, iv_b)

print(f"\n  Experimento 2 — IVs distintos")
print(f"  IV-A      : {iv_a.hex()}")
print(f"  IV-B      : {iv_b.hex()}")
print(f"  Cifrado A : {ct_2a.hex()}")
print(f"  Cifrado B : {ct_2b.hex()}")
print(f"  Resultado : {'DISTINTOS' if ct_2a != ct_2b else 'IDENTICOS'}")


# ANÁLISIS 2.5 — Padding PKCS#7
header("ANÁLISIS 2.5 — Padding PKCS#7")

BLOCK_SIZE = 8

for msg, desc in [
    (b"Hola!",      "5 bytes"),
    (b"12345678",   "8 bytes — bloque exacto"),
    (b"Hola mundo", "10 bytes"),
]:
    padded    = pkcs7_pad(msg, BLOCK_SIZE)
    recovered = pkcs7_unpad(padded, BLOCK_SIZE)

    print(f"\n  Mensaje ({desc}): {msg!r}")
    print(f"  Original   ({len(msg):>2}B): {msg.hex()}")
    print(f"  Con padding({len(padded):>2}B): {padded.hex()}")

    if len(msg) % BLOCK_SIZE == 0:
        print(f"  Padding: bloque completo de {BLOCK_SIZE} x 0x{BLOCK_SIZE:02x}")
    else:
        faltaban = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
        print(f"  Padding: {faltaban} x 0x{faltaban:02x} = {bytes([faltaban]*faltaban).hex()}")

    print(f"  Recuperado : {recovered!r}  ({'correcto' if recovered == msg else 'ERROR'})")
