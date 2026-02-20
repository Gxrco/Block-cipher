"""
Módulo de padding PKCS#7 para cifrados de bloque.
Implementación manual sin usar bibliotecas externas.
"""

def pkcs7_pad(data: bytes, block_size: int = 8):
    """
    Implementa padding PKCS#7 según RFC 5652.

    Regla: Si faltan N bytes para completar el bloque,
    agregar N bytes, cada uno con el valor N (recuerden seguir la regla de pkcs#7).

    Importante: Si el mensaje es múltiplo exacto del tamaño
    de bloque, se agrega un bloque completo de padding.

    Examples:
        >>> pkcs7_pad(b"HOLA", 8).hex()
        '484f4c4104040404'  # HOLA + 4 bytes con valor 0x04

        >>> pkcs7_pad(b"12345678", 8).hex()  # Exactamente 8 bytes
        '31323334353637380808080808080808'  # + bloque completo
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Elimina padding PKCS#7 de los datos.

    Examples:
        >>> padded = pkcs7_pad(b"HOLA", 8)
        >>> pkcs7_unpad(padded)
        b'HOLA'
    """
    padding_length = data[-1]
    return data[:-padding_length]