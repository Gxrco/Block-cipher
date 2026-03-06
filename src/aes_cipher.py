"""
Módulo de cifrado AES-256 en modos ECB y CBC.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from src.generacion_llaves import generate_aes_key, generate_iv


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra datos usando AES en modo ECB.

    Args:
        plaintext: Datos a cifrar
        key: Clave AES de 16, 24 o 32 bytes

    Returns:
        Datos cifrados
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, 16)
    return cipher.encrypt(padded)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra datos usando AES en modo ECB.

    Args:
        ciphertext: Datos cifrados
        key: Clave AES de 16, 24 o 32 bytes

    Returns:
        Datos descifrados sin padding
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, 16)


def aes_cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra datos usando AES en modo CBC.

    Genera un IV aleatorio de 16 bytes y lo concatena al inicio del resultado.

    Args:
        plaintext: Datos a cifrar
        key: Clave AES de 16, 24 o 32 bytes

    Returns:
        IV (16 bytes) + datos cifrados
    """
    iv = generate_iv(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, 16)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Descifra datos usando AES en modo CBC.

    Espera que los primeros 16 bytes sean el IV.

    Args:
        data: IV (16 bytes) + datos cifrados
        key: Clave AES de 16, 24 o 32 bytes

    Returns:
        Datos descifrados sin padding
    """
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, 16)

"""
Demostración de AES-256 en modos ECB y CBC.
"""
if __name__ == "__main__":
    key = generate_aes_key(256)  # 32 bytes
    message = b"Hola Mundo - AES Test Message"

    print(f"Original: {message}")
    print(f"Key (256-bit): {key.hex()}")

    # Test ECB
    encrypted_ecb = aes_ecb_encrypt(message, key)
    print(f"\nECB Encrypted: {encrypted_ecb.hex()}")
    decrypted_ecb = aes_ecb_decrypt(encrypted_ecb, key)
    print(f"ECB Decrypted: {decrypted_ecb}")
    assert decrypted_ecb == message, "ECB round-trip failed!"
    print("AES-ECB round-trip OK")

    # Test CBC
    encrypted_cbc = aes_cbc_encrypt(message, key)
    print(f"\nCBC IV + Ciphertext: {encrypted_cbc.hex()}")
    print(f"CBC IV: {encrypted_cbc[:16].hex()}")
    decrypted_cbc = aes_cbc_decrypt(encrypted_cbc, key)
    print(f"CBC Decrypted: {decrypted_cbc}")
    assert decrypted_cbc == message, "CBC round-trip failed!"
    print("AES-CBC round-trip OK")
