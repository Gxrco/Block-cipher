"""
Demostración completa del laboratorio de cifrado de bloque.
Prompt: Dados los métodos implementados en src/ como AES, DES, 3DES, padding PKCS#7, y procesamiento de imágenes, este script realiza las siguientes demostraciones:
1. Padding manual PKCS#7: muestra cómo se añaden y eliminan los bytes de padding.
2. DES-ECB: cifra y descifra el contenido de des.txt, mostrando el texto
original, el cifrado (en hexadecimal) y el texto descifrado.
3. 3DES-CBC: cifra y descifra el contenido de 3des.txt, mostrando el texto
original, el IV utilizado, el cifrado (en hexadecimal) y el texto descifrado.
4. AES-ECB con bloques repetidos: muestra cómo el cifrado ECB revela patrones en un mensaje con bloques idénticos, mientras que CBC no lo hace.
5. Cifrado visual de imágenes: convierte pic.png a BMP si es necesario, luego cifra la imagen usando AES-ECB y AES-CBC, guardando los resultados en outputs/pic_ecb.bmp y outputs/pic_cbc.bmp respectivamente, para comparar visualmente los efectos del cifrado.
6. Experimento con IV: muestra cómo reutilizar el mismo IV en CBC produce el mismo cifrado para el mismo mensaje, mientras que usar un IV diferente produce cifrados distintos, demostrando la importancia de un IV único por operación.    
"""
import os

from src.manual_padding import pkcs7_pad, pkcs7_unpad
from src.des_ecb import des_encrypt, des_decrypt
from src.triple_des_cbc import tdes_encrypt, tdes_decrypt
from src.aes_cipher import (
    aes_ecb_encrypt, aes_ecb_decrypt,
    aes_cbc_encrypt, aes_cbc_decrypt
)
from src.image_process import encrypt_image_ecb, encrypt_image_cbc, convert_png_to_bmp
from src.generacion_llaves import (
    generate_des_key, generate_3des_key, generate_aes_key, generate_iv
)


def separator(title: str) -> None:
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def demo_padding():
    """1. Demostración de padding manual PKCS#7."""
    separator("1. PADDING MANUAL PKCS#7")

    # Ejemplo básico
    data = b"HOLA"
    padded = pkcs7_pad(data, 8)
    print(f"Original: {data} ({len(data)} bytes)")
    print(f"Padded:   {padded.hex()} ({len(padded)} bytes)")
    print(f"Unpadded: {pkcs7_unpad(padded)}")

    # Múltiplo exacto
    data = b"12345678"
    padded = pkcs7_pad(data, 8)
    print(f"\nMúltiplo exacto: {data} ({len(data)} bytes)")
    print(f"Padded:   {padded.hex()} ({len(padded)} bytes)")
    print(f"Unpadded: {pkcs7_unpad(padded)}")


def demo_des_ecb():
    """2. Demostración de DES-ECB con des.txt."""
    separator("2. DES-ECB")

    key = generate_des_key()
    print(f"Clave DES (8 bytes): {key.hex()}")

    with open("des.txt", "rb") as f:
        plaintext = f.read()

    print(f"\nPlaintext ({len(plaintext)} bytes):")
    print(plaintext[:100].decode() + "...")

    ciphertext = des_encrypt(plaintext, key)
    print(f"\nCiphertext ({len(ciphertext)} bytes):")
    print(ciphertext[:64].hex() + "...")

    decrypted = des_decrypt(ciphertext, key)
    print(f"\nDecrypted ({len(decrypted)} bytes):")
    print(decrypted[:100].decode() + "...")

    assert decrypted == plaintext
    print("\n✓ DES-ECB round-trip verificado")


def demo_3des_cbc():
    """3. Demostración de 3DES-CBC con 3des.txt."""
    separator("3. 3DES-CBC")

    key = generate_3des_key(2)  # 16 bytes
    print(f"Clave 3DES (16 bytes): {key.hex()}")

    with open("3des.txt", "rb") as f:
        plaintext = f.read()

    print(f"\nPlaintext ({len(plaintext)} bytes):")
    print(plaintext[:100].decode() + "...")

    # Cifrar (IV incluido en resultado)
    encrypted = tdes_encrypt(plaintext, key)
    iv = encrypted[:8]
    ciphertext = encrypted[8:]

    print(f"\nIV (8 bytes): {iv.hex()}")
    print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext[:64].hex()}...")

    # Descifrar
    decrypted = tdes_decrypt(encrypted, key)
    print(f"\nDecrypted ({len(decrypted)} bytes):")
    print(decrypted[:100].decode() + "...")

    assert decrypted == plaintext
    print("\n✓ 3DES-CBC round-trip verificado")


def demo_aes_repeated_blocks():
    """4. Demostración de vulnerabilidad ECB con bloques repetidos."""
    separator("4. AES - VULNERABILIDAD ECB (Bloques Repetidos)")

    key = generate_aes_key(256)
    print(f"Clave AES-256: {key.hex()[:32]}...")

    # Mensaje con bloques idénticos
    block = b"BLOQUE_REPETIDO!"  # 16 bytes exactos
    message = block * 4  # 4 bloques idénticos

    print(f"\nMensaje: {message}")
    print(f"Longitud: {len(message)} bytes (4 bloques de 16)")

    # ECB: bloques idénticos producen cifrado idéntico
    encrypted_ecb = aes_ecb_encrypt(message, key)
    print(f"\nECB Cifrado:")
    for i in range(4):
        block_cipher = encrypted_ecb[i*16:(i+1)*16]
        print(f"  Bloque {i+1}: {block_cipher.hex()}")

    print("\n⚠ Observación: Todos los bloques ECB son IDÉNTICOS")
    print("  Esto revela patrones en el mensaje original.")

    # CBC: cada bloque es diferente
    encrypted_cbc = aes_cbc_encrypt(message, key)
    iv = encrypted_cbc[:16]
    ciphertext = encrypted_cbc[16:]

    print(f"\nCBC Cifrado (IV: {iv.hex()[:16]}...):")
    for i in range(4):
        block_cipher = ciphertext[i*16:(i+1)*16]
        print(f"  Bloque {i+1}: {block_cipher.hex()}")

    print("\n✓ CBC produce bloques DIFERENTES aunque el mensaje sea repetido")


def demo_aes_images():
    """5. Cifrado visual de imágenes."""
    separator("5. AES - CIFRADO VISUAL DE IMÁGENES")

    png_source = "pic.png"
    bmp_source = "assets/pic.bmp"
    ecb_output = "outputs/pic_ecb.bmp"
    cbc_output = "outputs/pic_cbc.bmp"

    # Convertir si es necesario
    if not os.path.exists(bmp_source) and os.path.exists(png_source):
        print(f"Convirtiendo {png_source} a BMP...")
        convert_png_to_bmp(png_source, bmp_source)

    if not os.path.exists(bmp_source):
        print(f"⚠ No se encontró imagen. Saltando demo de imágenes.")
        return

    key = generate_aes_key(256)
    iv = generate_iv(16)

    print(f"Clave AES-256: {key.hex()[:32]}...")
    print(f"IV: {iv.hex()}")

    encrypt_image_ecb(bmp_source, key, ecb_output)
    print(f"\n✓ ECB cifrado: {ecb_output}")

    encrypt_image_cbc(bmp_source, key, iv, cbc_output)
    print(f"✓ CBC cifrado: {cbc_output}")

    print("\nComparación visual esperada:")
    print("  - ECB: Patrones y formas de la imagen original visibles")
    print("  - CBC: Ruido completamente aleatorio")


def demo_iv_experiment():
    """6. Experimento con IV: mismo IV vs IV diferente."""
    separator("6. EXPERIMENTO IV - Reutilización de IV")

    key = generate_aes_key(256)
    message = b"Mensaje secreto para experimento IV"

    print(f"Mensaje: {message}")
    print(f"Clave: {key.hex()[:32]}...")

    # Mismo IV (MALO)
    fixed_iv = generate_iv(16)
    print(f"\n--- Mismo IV (vulnerable) ---")
    print(f"IV fijo: {fixed_iv.hex()}")

    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    cipher1 = AES.new(key, AES.MODE_CBC, fixed_iv)
    ct1 = cipher1.encrypt(pad(message, 16))

    cipher2 = AES.new(key, AES.MODE_CBC, fixed_iv)
    ct2 = cipher2.encrypt(pad(message, 16))

    print(f"Cifrado 1: {ct1.hex()}")
    print(f"Cifrado 2: {ct2.hex()}")
    print(f"¿Idénticos? {'SÍ ⚠' if ct1 == ct2 else 'NO'}")

    # IV diferente (CORRECTO)
    print(f"\n--- IV aleatorio por operación (seguro) ---")

    encrypted1 = aes_cbc_encrypt(message, key)
    encrypted2 = aes_cbc_encrypt(message, key)

    print(f"IV 1: {encrypted1[:16].hex()}")
    print(f"IV 2: {encrypted2[:16].hex()}")
    print(f"Cifrado 1: {encrypted1[16:].hex()}")
    print(f"Cifrado 2: {encrypted2[16:].hex()}")
    print(f"¿Idénticos? {'SÍ ⚠' if encrypted1 == encrypted2 else 'NO ✓'}")

    print("\n✓ Usar IV aleatorio previene que el atacante detecte mensajes repetidos")


def main():
    print("\n" + "="*60)
    print(" LABORATORIO DE CIFRADO DE BLOQUE")
    print("="*60)

    demo_padding()
    demo_des_ecb()
    demo_3des_cbc()
    demo_aes_repeated_blocks()
    demo_aes_images()
    demo_iv_experiment()

    separator("FIN DE LA DEMOSTRACIÓN")


if __name__ == "__main__":
    main()
