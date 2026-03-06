"""
Módulo de cifrado DES en modo ECB.
Usa padding manual PKCS#7 del módulo manual_padding.
"""
from Crypto.Cipher import DES

from src.manual_padding import pkcs7_pad, pkcs7_unpad
from src.generacion_llaves import generate_des_key


def des_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra datos usando DES en modo ECB con padding PKCS#7.

    Args:
        plaintext: Datos a cifrar
        key: Clave DES de 8 bytes

    Returns:
        Datos cifrados
    """
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pkcs7_pad(plaintext, 8)
    return cipher.encrypt(padded)


def des_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra datos usando DES en modo ECB y remueve padding PKCS#7.

    Args:
        ciphertext: Datos cifrados
        key: Clave DES de 8 bytes

    Returns:
        Datos descifrados sin padding
    """
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return pkcs7_unpad(decrypted)

"""
Demostración de DES en modo ECB.
"""
if __name__ == "__main__":
    key = generate_des_key()
    message = b"Hola Mundo - DES ECB Test"

    print(f"Original: {message}")
    print(f"Key: {key.hex()}")

    encrypted = des_encrypt(message, key)
    print(f"Encrypted: {encrypted.hex()}")

    decrypted = des_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")

    assert decrypted == message, "Round-trip failed!"
    print("DES-ECB round-trip OK")
