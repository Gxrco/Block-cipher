"""
Generador de claves criptográficamente seguras.
"""
import secrets


def generate_des_key():
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).

    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.

    """
    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 2):
    """
    Genera una clave 3DES aleatoria.

    key_option 1: 8 bytes (DES simple)
    key_option 2: 16 bytes (3DES con 2 claves)
    key_option 3: 24 bytes (3DES con 3 claves)
    """
    key_sizes = {1: 8, 2: 16, 3: 24}
    return secrets.token_bytes(key_sizes.get(key_option, 16))


def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.

    key_size: 128, 192 o 256 bits
    """
    return secrets.token_bytes(key_size // 8)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    block_size: tamaño en bytes (8 para DES/3DES, 16 para AES)
    """
    return secrets.token_bytes(block_size)