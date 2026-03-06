"""
Módulo para cifrado visual de imágenes BMP.
Cifra solo los píxeles, manteniendo el header intacto.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from src.generacion_llaves import generate_aes_key, generate_iv

# Header BMP estándar: 54 bytes
BMP_HEADER_SIZE = 54


def encrypt_image_ecb(img_path: str, key: bytes, out_path: str) -> None:
    """
    Cifra los píxeles de una imagen BMP usando AES-ECB.

    El header (54 bytes) se mantiene intacto para que la imagen
    siga siendo válida y se pueda visualizar.

    Args:
        img_path: Ruta a la imagen BMP de entrada
        key: Clave AES de 16, 24 o 32 bytes
        out_path: Ruta de salida para la imagen cifrada
    """
    with open(img_path, "rb") as f:
        data = f.read()

    header = data[:BMP_HEADER_SIZE]
    pixels = data[BMP_HEADER_SIZE:]

    cipher = AES.new(key, AES.MODE_ECB)
    # Padding para que sea múltiplo de 16
    padded_pixels = pad(pixels, 16)
    encrypted_pixels = cipher.encrypt(padded_pixels)
    # Recortar al tamaño original de píxeles
    encrypted_pixels = encrypted_pixels[:len(pixels)]

    with open(out_path, "wb") as f:
        f.write(header + encrypted_pixels)


def encrypt_image_cbc(img_path: str, key: bytes, iv: bytes, out_path: str) -> None:
    """
    Cifra los píxeles de una imagen BMP usando AES-CBC.

    El header (54 bytes) se mantiene intacto para que la imagen
    siga siendo válida y se pueda visualizar.

    Args:
        img_path: Ruta a la imagen BMP de entrada
        key: Clave AES de 16, 24 o 32 bytes
        iv: Vector de inicialización de 16 bytes
        out_path: Ruta de salida para la imagen cifrada
    """
    with open(img_path, "rb") as f:
        data = f.read()

    header = data[:BMP_HEADER_SIZE]
    pixels = data[BMP_HEADER_SIZE:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_pixels = pad(pixels, 16)
    encrypted_pixels = cipher.encrypt(padded_pixels)
    # Recortar al tamaño original de píxeles
    encrypted_pixels = encrypted_pixels[:len(pixels)]

    with open(out_path, "wb") as f:
        f.write(header + encrypted_pixels)


def convert_png_to_bmp(png_path: str, bmp_path: str) -> None:
    """
    Convierte una imagen PNG a formato BMP.

    Args:
        png_path: Ruta a la imagen PNG
        bmp_path: Ruta de salida para la imagen BMP
    """
    from PIL import Image
    img = Image.open(png_path)
    img = img.convert("RGB")
    img.save(bmp_path, "BMP")


"""
Demostración de cifrado visual de imágenes BMP usando AES-ECB y AES-CBC.
"""
if __name__ == "__main__":
    import os

    png_source = "pic.png"
    bmp_source = "assets/pic.bmp"
    ecb_output = "outputs/pic_ecb.bmp"
    cbc_output = "outputs/pic_cbc.bmp"

    # Convertir PNG a BMP si no existe
    if not os.path.exists(bmp_source) and os.path.exists(png_source):
        print(f"Convirtiendo {png_source} a BMP...")
        convert_png_to_bmp(png_source, bmp_source)

    if not os.path.exists(bmp_source):
        print(f"Error: No se encontró imagen en {bmp_source}")
        exit(1)

    key = generate_aes_key(256)
    iv = generate_iv(16)

    print(f"Key: {key.hex()}")
    print(f"IV: {iv.hex()}")

    # Cifrar con ECB
    encrypt_image_ecb(bmp_source, key, ecb_output)
    print(f"ECB encrypted: {ecb_output}")

    # Cifrar con CBC
    encrypt_image_cbc(bmp_source, key, iv, cbc_output)
    print(f"CBC encrypted: {cbc_output}")

    print("\nComparación visual:")
    print("- ECB: Patrones de la imagen original aún visibles")
    print("- CBC: Imagen completamente ruidosa (pseudoaleatoria)")
