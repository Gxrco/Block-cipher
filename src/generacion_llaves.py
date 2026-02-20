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
    
    return True


def generate_3des_key(key_option: int = 2):
    """
    Genera una clave 3DES aleatoria.   

    """

    return True


def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.
    
   
    """
    # TODO: Implementar
    # Convertir bits a bytes: key_size // 8
    pass


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    """
    # TODO: Implementar
    pass