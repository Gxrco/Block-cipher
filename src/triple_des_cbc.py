"""
Módulo de cifrado 3DES en modo CBC.
Usa padding de PyCryptodome (no manual).
"""
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

from src.generacion_llaves import generate_3des_key, generate_iv


def tdes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra datos usando 3DES en modo CBC.

    Genera un IV aleatorio de 8 bytes y lo concatena al inicio del resultado.

    Args:
        plaintext: Datos a cifrar
        key: Clave 3DES de 16 o 24 bytes

    Returns:
        IV (8 bytes) + datos cifrados
    """
    iv = generate_iv(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pad(plaintext, 8)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def tdes_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Descifra datos usando 3DES en modo CBC.

    Espera que los primeros 8 bytes sean el IV.

    Args:
        data: IV (8 bytes) + datos cifrados
        key: Clave 3DES de 16 o 24 bytes

    Returns:
        Datos descifrados sin padding
    """
    iv = data[:8]
    ciphertext = data[8:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, 8)

"""
Demostración de 3DES en modo CBC.
"""
if __name__ == "__main__":
    key = generate_3des_key(2)  # 16 bytes
    message = b"Hola Mundo - 3DES CBC Test"

    print(f"Original: {message}")
    print(f"Key: {key.hex()}")

    encrypted = tdes_encrypt(message, key)
    print(f"IV + Ciphertext: {encrypted.hex()}")
    print(f"IV: {encrypted[:8].hex()}")

    decrypted = tdes_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")

    assert decrypted == message, "Round-trip failed!"
    print("3DES-CBC round-trip OK")
